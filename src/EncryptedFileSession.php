<?php

namespace Oonix;

/**
 * Encrypted Sessions
 *
 * Filesystem storage of encrypted sessions.
 * 
 * @package oonix/encrypted-sessions
 * @author Arran Schlosberg <arran@oonix.com.au>
 * @license GPL-3.0
 */
class EncryptedFileSession extends EncryptedSessionHandler {

	/**
	 * Convenience wrapper to determine the full path of the session storage file in keeping with standard PHP file-based sessions.
	 *
	 * @param string $key
	 */
	private function path($key){
		return "{$this->_save_path}/sess_{$key}";
	}

	/**
	 * Implementation of EncryptedSessionHandler::get()
	 */
	public function get($key){
		$path = $this->path($key);
		return file_exists($path) ? file_get_contents($path) : null;
	}

	/**
	 * Implementation of EncryptedSessionHandler::put()
	 */	
	public function put($key, $data){
		$path = $this->path($key);
		return file_put_contents($path, $data) && chmod($path, 0600);
	}
	
	/**
	 * Implementation of EncryptedSessionHandler::remove()
	 */
	public function remove($key){
		$path = $this->path($key);
		return !file_exists($path) || unlink($path);
	}

	/**
	 * Implementation of SessionHandlerInterface::gc()
	 */	
	public function gc($maxlifetime){
		$success = true;
		foreach(glob($this->path("*")) as $file){
			if(file_exists($file) && filemtime($file) + $maxlifetime < time()) {
				$success = $success && unlink($file);
			}
		}
		return $success;
	}

}

?>
