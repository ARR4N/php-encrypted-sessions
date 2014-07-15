<?php

ini_set('display_errors', true);

require "src/EncryptedSessionException.php";
require "src/EncryptedSessionHandler.php";
require "src/EncryptedFileSession.php";

//class to expose otherwise private data for the purpose of the demo
class DemoSession extends Oonix\EncryptedFileSession {
	private $storageKey;
	
	public function get($key){
		$this->storageKey = $key;
		return parent::get($key);
	}
	
	public function raw(){ //get() usually requires the storage key but we save it the first time
		return $this->get($this->storageKey);
	}
	
	public function storagePath(){
		return "{$this->_save_path}/sess_{$this->storageKey}";
	}
}

try {
	$handler = new DemoSession('AES-128-CBC', 'sha1', 'w4fvdIuGLnF7i8DicF75Z8mPPo4tUyGRvcvHvdknwxCmbpOENpVn0TBBpryRQOKD');
	session_set_save_handler($handler);
	session_start();
}
catch(Oonix\EncryptedSessionException $e){
	var_dump($e);
}

if(isset($_POST['do'])){
	switch($_POST['do']){
		case 'save':
			$_SESSION[$_POST['key']] = $_POST['val'];
			break;
		case 'remove':
			unset($_SESSION[$_POST['key']]);
			break;
	}
}
?>

<form method="post" action="./demo.php">
	Key: <input name="key" />
	Val: <input name="val" />
	<select name="do">
		<option value="save">Save</option>
		<option value="remove">Remove</option>
	</select>
	<input type="submit" />
</form>

<h3>Current session data</h3>
<?php var_dump($_SESSION); ?>

<h3>Session ID (secret anyway; used to derive encryption and storage keys with HMAC)</h3>
<?php var_dump(session_id()); ?>

<h3>Storage path (derived from encryption key with HMAC)</h3>
<?php var_dump($handler->storagePath()); ?>

<h3>Raw cipher text and IV</h3>
<?php var_dump($handler->raw()); ?>
