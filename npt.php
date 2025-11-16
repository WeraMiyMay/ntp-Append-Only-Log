#!/usr/bin/env php
<?php
declare(strict_types=1);

const DATA_FILE = 'data.npt';
const KEYS_FILE = 'keys.json';
const ALLOWLIST_FILE = 'allowlist.json';

const MAGIC = "NOVIJ1"; // 6 байт
const MAGIC_LEN = 6;
const PUBKEY_LEN = 32;
const SIG_LEN = 64;
const HASH_LEN = 32;

?>