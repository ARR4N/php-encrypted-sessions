<?php

namespace Oonix;

/**
 * Encrypted Sessions
 *
 * Abstract class for [en|de]crypting session data, using the session ID as the encryption key as it should be kept private anyway.
 * HMACs
 * 
 * @package oonix/encrypted-sessions
 * @author Arran Schlosberg <arran@oonix.com.au>
 * @license GPL-3.0
 */
abstract class EncryptedSessionHandler implements \SessionHandlerInterface {
	
	/**
	 * Cipher method to be used. See openssl_encrypt() for details.
	 *
	 * @var string
	 * @access private
	 */
	private $_cipher;
	
	/**
	 * Hash function to use in determining the encryption and storage keys from the session ID. See EncryptedSessionHandler::convertKey() for details.
	 *
	 * @var string
	 * @access private
	 */
	private $_hash;
	
	/**
	 * Entropy for use as HMAC data in determining encryption and storage keys from the session ID.
	 * Requires a compromise of session data, session ID, and application data to access encrypted content.
	 * Should remain constant across all requests.
	 *
	 * @var string
	 * @access private
	 */
	private $_entropy;
	
	/**
	 * Storage of the save-path as passed to SessionHandlerInterface::open().
	 *
	 * @var string
	 * @access private
	 */
	protected $_save_path;
	
	/**
	 * Storage of the session name as passed to SessionHandlerInterface::open().
	 *
	 * @var string
	 * @access private
	 */
	protected $_name;
	
	/**
	 * Should we allow the initialisation vector for the encryption to be derived from a cryptographically weak PRNG
	 *
	 * @var bool
	 * @access private
	 */
	private $_allow_weak_iv;

	/**
	 * Constructor
	 *
	 * Store the configuration directives. Implements checks and then stores each in the equivalent private parameter.
	 *
	 * @param string $cipher			See attribute $_cipher.
	 * @param string $hash				See attribute $_hash.
	 * @param string $entropy			See attribute $_entropy; must be at least 64 characters.
	 * @param bool   $allow_weak_iv	See attribute $_allow_weak_iv.
	 * @access public
	 */
	public function __construct($cipher, $hash, $entropy, $allow_weak_iv = false){
		if(!function_exists('openssl_encrypt')){
			throw new EncryptedSessionException("OpenSSL encryption functions required.");
		}
		
		if(!in_array($cipher, openssl_get_cipher_methods(true))){
			throw new EncryptedSessionException("The cipher '{$cipher}' is not available. Use openssl_get_cipher_methods() for a list of available methods.");
		}
		$this->_cipher = $cipher;
		
		if(!in_array($hash, hash_algos())){
			throw new EncryptedSessionException("The hash algorithm '{$hash}' is not available. Use hash_algos() for a list of available algorithms.");
		}
		$this->_hash = $hash;
		
		if(strlen($entropy)<64){
			throw new EncryptedSessionException("Please provide at least 64 characters of entropy.");
		}
		$this->_entropy = $entropy;
		
		$this->_allow_weak_iv = $allow_weak_iv===true;
	}
	
	/**
	 * Abstract function for retrieving saved session data.
	 *
	 * @param string $key	The unique storage key. See EncryptedSessionHandler::convertKey() for details.
	 * @access public
	 * @return string			Stored session data.
	 */
	public abstract function get($key);
	
	/**
	 * Abstract function for storing session data.
	 *
	 * @param string $key	The unique storage key. See EncryptedSessionHandler::convertKey() for details.
	 * @param string $data	Encrypted session data to be stored.
	 * @access public
	 * @return bool			Success
	 */
	public abstract function put($key, $data);
	
	/**
	 * Abstract function for removing a stored session.
	 *
	 * @param string $key	The unique storage key. See EncryptedSessionHandler::convertKey() for details.
	 * @access public
	 * @return bool			Success
	 */
	public abstract function remove($key);

	/**
	 * Implementation of SessionHandlerInterface::open()
	 *
	 * Store the save-path and session name. These may be ignored by some extensions (e.g. database) but the function is implemented to save extensions having to do so.
	 */
	public function open($save_path, $name){
		$this->_save_path = $save_path;
		$this->_name = $name;
		return true;
	}

	/**
	 * Implementation of SessionHandlerInterface::close()
	 *
	 * Does nothing but the function is implemented to save extensions having to do so.
	 */
	public function close(){
		return true;
	}
	
	/**
	 * Derive encryption and session keys from the session ID.
	 *
	 * As the session ID is private it can additionally be used to encrypt the data at rest as long as the storage key does not reveal information as to the ID.
	 * The ID is used as the secret key for HMAC derivation with $_entropy (see constructor) used as data.
	 *
	 * - First round HMAC returns raw data to be used as the key for openssl_[en|de]crypt()
	 * - Secound round HMAC is base64 encoded, truncated to the standard 26 string-length and used as the storage key.
	 *
	 * @param string $key	The session ID.
	 * @access public
	 * @return array			Encryption and storage keys.
	 */
	private function convertID($id){
		$enc = hash_hmac($this->_hash, $this->_entropy, $id, true);
		$store = hash_hmac($this->_hash, $this->_entropy, $enc, true);
		return array('enc' => $enc, 'store' => substr(base64_encode($store), 0, 26));
	}
	
	/**
	 * Implementation of SessionHandlerInterface::write()
	 *
	 * Convert the session ID into encryption and storage keys and pass encrypted data to EncryptedSessionHandler::put().
	 * Initialisation vector and ciphertext are stored in a seralized array.
	 */
	public function write($id, $data){
		/**
		 * Generate an IV and ensure that requirements for a cryptographically strong algorithm are met.
		 */
		$strong = false;
		$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->_cipher), $strong);
		if(!$strong && $this->_allow_weak_iv!==true){
			throw new EncryptedSessionException("A cryptographically weak algorithm was used in the generation of the initialisation vector.");
		}
		
		$keys = $this->convertID($id);

		$data = array(
			'iv' => base64_encode($iv),
			'data' => openssl_encrypt($data, $this->_cipher, $keys['enc'], 0, $iv)
		);
		
		return $this->put($keys['store'], serialize($data));
	}
	
	/**
	 * Implementation of SessionHandlerInterface::read()
	 *
	 * Convert the session ID into encryption and storage keys and decrypt data from EncryptedSessionHandler::get().
	 * Initialisation vector and ciphertext are stored in a seralized array.
	 */
	public function read($id){
		$keys = $this->convertID($id);
		$data = unserialize($this->get($keys['store']));
		$iv = base64_decode($data['iv']);
		return openssl_decrypt($data['data'], $this->_cipher, $keys['enc'], 0, $iv);
	}

	/**
	 * Implementation of SessionHandlerInterface::destroy()
	 *
	 * Convert the session ID into encryption and storage keys and pass the latter to EncryptedSessionHandler::remove().
	 */
	public function destroy($id){
		return $this->remove($this->convertID($key)['file']);
	}
}
