#!/usr/bin/env php
<?php
declare(strict_types=1);

if (!extension_loaded('sodium')) {
    fwrite(STDERR, "Ошибка: требуется ext-sodium.\n");
    exit(1);
}

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "Работает только в CLI.\n");
    exit(1);
}

$argv = $_SERVER['argv'];
$argc = $_SERVER['argc'];

if ($argc < 2) {
    fwrite(STDERR, "Использование: php npt.php <команда>\n");
    exit(1);
}

$command = $argv[1];

switch ($command) {

    case 'init':
        cmd_init();
        break;

    case 'write':
        cmd_write($argv);
        break;

    case 'generate':
        cmd_generate($argv);
        break;

    case 'read':
        cmd_read($argv);
        break;

    case 'verify':
        cmd_verify();
        break;
    
    case 'export':
        cmd_export();
        break;

    case 'search':
        cmd_search($argv);
        break;    

    default:
        fwrite(STDERR, "Неизвестная команда: $command\n");
        exit(1);
}

/* --------------------------- INIT -------------------------- */

function cmd_init(): void {
    if (file_exists('data.npt')) {
        fwrite(STDERR, "Ошибка: data.npt уже существует.\n");
        exit(1);
    }
    if (file_exists('keys.json') || file_exists('allowlist.json')) {
        fwrite(STDERR, "Ошибка: keys.json или allowlist.json уже существуют.\n");
        exit(1);
    }

    file_put_contents('data.npt', '');

    $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
    $keypair = sodium_crypto_sign_seed_keypair($seed);
    $pk = sodium_crypto_sign_publickey($keypair);
    $sk = sodium_crypto_sign_secretkey($keypair);

    file_put_contents('keys.json', json_encode([
        'public' => bin2hex($pk),
        'secret' => bin2hex($sk),
        'seed'   => bin2hex($seed),
        'created'=> time(),
    ], JSON_PRETTY_PRINT));

    file_put_contents('allowlist.json', json_encode([bin2hex($pk)], JSON_PRETTY_PRINT));

    fwrite(STDOUT, "init ок\n");
}

/* --------------------------- WRITE -------------------------- */

function cmd_write(array $argv): void {
    if (!in_array('--stdin', $argv, true)) {
        fwrite(STDERR, "Использование: php npt.php write --stdin\n");
        exit(1);
    }

    $payload = stream_get_contents(STDIN);
    if ($payload === false || trim($payload) === '') {
        fwrite(STDERR, "Ошибка: пустой STDIN.\n");
        exit(1);
    }

    json_decode($payload, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        fwrite(STDERR, "Ошибка: STDIN не JSON.\n");
        exit(1);
    }

    write_block($payload);
    fwrite(STDOUT, "ok\n");
}

/* ------------------------- GENERATE ------------------------- */

function cmd_generate(array $argv): void {
    $count = null;
    $randomMode = false;
    $templatePath = null;

    // ---- Разбор аргументов ----
    for ($i = 0; $i < count($argv); $i++) {
        if ($argv[$i] === '--count' && isset($argv[$i+1])) {
            $count = (int)$argv[$i+1];
        }
        if ($argv[$i] === '--random') {
            $randomMode = true;
        }
        if ($argv[$i] === '--template' && isset($argv[$i+1])) {
            $templatePath = $argv[$i+1];
        }
    }

    if ($count === null || $count <= 0) {
        fwrite(STDERR, "Использование: php npt.php generate --count N [--template path.json | --random]\n");
        exit(1);
    }

    if ($randomMode && $templatePath !== null) {
        fwrite(STDERR, "Ошибка: одновременно указаны --random и --template.\n");
        exit(1);
    }

    // ---- Загрузка шаблона ----
    $template = null;
    if ($templatePath !== null) {

        if (!file_exists($templatePath)) {
            fwrite(STDERR, "Ошибка: не найден template: $templatePath\n");
            exit(1);
        }

        $tplRaw = file_get_contents($templatePath);
        if ($tplRaw === false) {
            fwrite(STDERR, "Ошибка: невозможно прочитать template.\n");
            exit(1);
        }

        // -------- Обработка BOM и кодировок --------

        // Если UTF‑16LE или UTF‑16BE
        if (substr($tplRaw, 0, 2) === "\xFF\xFE" || substr($tplRaw, 0, 2) === "\xFE\xFF") {
            $tplRaw = mb_convert_encoding($tplRaw, 'UTF-8', 'UTF-16');
        }

        // Удаляем UTF‑8 BOM
        if (substr($tplRaw, 0, 3) === "\xEF\xBB\xBF") {
            $tplRaw = substr($tplRaw, 3);
        }

        // Удаляем управляющие символы вне UTF‑8
        $tplRaw = preg_replace('/[^\x09\x0A\x0D\x20-\x7E\xC2-\xF4][^\x80-\xBF]*/', '', $tplRaw);

        // Трим
        $tplRaw = trim($tplRaw);

        // -------- Парсинг JSON --------
        $template = json_decode($tplRaw, true);

        if ($template === null || json_last_error() !== JSON_ERROR_NONE) {
            fwrite(STDERR, "Ошибка: template невалидный JSON. Причина: " . json_last_error_msg() . "\n");
            exit(1);
        }

        // Template должен быть JSON‑объектом { ... }
        if (!is_array($template) || array_is_list($template)) {
            fwrite(STDERR, "Ошибка: template должен быть JSON‑объектом { ... }.\n");
            exit(1);
        }
    }

    // ---- Генерация блоков ----
    for ($i = 0; $i < $count; $i++) {

        $now = time();

        if ($randomMode) {

            $payloadArray = [
                'id'  => $i + 1,
                'ts'  => $now,
                'rnd' => bin2hex(random_bytes(8)),
                'val' => random_int(0, PHP_INT_MAX)
            ];

        } elseif ($template !== null) {

            $payloadArray = $template;
            $payloadArray['id'] = $i + 1;
            $payloadArray['ts'] = $now;

        } else {

            $payloadArray = [
                'id' => $i + 1,
                'ts' => $now
            ];
        }

        $payload = json_encode($payloadArray, JSON_UNESCAPED_SLASHES);
        write_block($payload);
    }

    fwrite(STDOUT, "Сгенерировано: $count\n");
}
/* ============================================================
 *  read_one_block_and_advance($fh)
 *  Возвращает массив полей или null в конце файла.
 * ============================================================ */
function read_one_block_and_advance($fh): ?array {
    $pos = ftell($fh);

    $magic = fread($fh, 6);
    if ($magic === false || strlen($magic) === 0) {
        return null; // EOF
    }
    if ($magic !== "NOVIJ1") {
        return ['error' => "MAGIC mismatch", 'offset' => $pos];
    }

    $LEN_raw = fread($fh, 4);
    if ($LEN_raw === false || strlen($LEN_raw) !== 4) {
        return ['error' => "bad LEN", 'offset' => $pos];
    }
    $LEN = unpack('N', $LEN_raw)[1];

    $body_raw = fread($fh, $LEN);
    if ($body_raw === false || strlen($body_raw) !== $LEN) {
        return ['error' => "body truncated", 'offset' => $pos];
    }

    $hash = fread($fh, 32);
    if ($hash === false || strlen($hash) !== 32) {
        return ['error' => "missing HASH", 'offset' => $pos];
    }

    // ---- Парсинг ----
    $c = 0;

    $ts_raw = substr($body_raw, $c, 8);
    $ts = unpack('J', $ts_raw)[1];
    $c += 8;

    $prev = substr($body_raw, $c, 32);
    $c += 32;

    $plen = unpack('N', substr($body_raw, $c, 4))[1];
    $c += 4;

    $payload_raw = substr($body_raw, $c, $plen);
    $payload = json_decode($payload_raw, true);
    $c += $plen;

    $pub = substr($body_raw, $c, 32);
    $c += 32;

    $sig = substr($body_raw, $c, 64);
    $c += 64;

    return [
        'offset'      => $pos,
        'ts'          => $ts,
        'ts_raw'      => $ts_raw,
        'prev'        => $prev,
        'payload'     => $payload,
        'payload_raw' => $payload_raw,
        'pub'         => $pub,
        'sig'         => $sig,
        'hash'        => $hash,

        'LEN_raw'     => $LEN_raw,
        'body_raw'    => $body_raw,
    ];
}

/* ============================================================
 *  write_block — общая функция записи блока
 * ============================================================ */

function write_block(string $payload): void {
    $keys = json_decode(file_get_contents('keys.json'), true);
    $pk = hex2bin($keys['public']);
    $sk = hex2bin($keys['secret']);

    $allow = json_decode(file_get_contents('allowlist.json'), true);
    if (!in_array(bin2hex($pk), $allow, true)) {
        fwrite(STDERR, "Ошибка: текущий ключ не в allowlist.\n");
        exit(1);
    }

    $fh = fopen('data.npt', 'c+b');
    if (!$fh) {
        fwrite(STDERR, "Не открыть data.npt\n");
        exit(1);
    }

    $prevHash = get_last_block_hash($fh);

    $ts = time();
    $tsBytes = pack('J', $ts);
    $plen = strlen($payload);
    $plenBytes = pack('N', $plen);

    $toSign = hash('sha256', $tsBytes . $prevHash . $payload, true);
    $sig = sodium_crypto_sign_detached($toSign, $sk);

    $body =
        $tsBytes .
        $prevHash .
        $plenBytes .
        $payload .
        $pk .
        $sig;

    $LEN = pack('N', strlen($body));

    $hash = hash('sha256', $LEN . $body, true);

    $block = "NOVIJ1" . $LEN . $body . $hash;

    fseek($fh, 0, SEEK_END);
    fwrite($fh, $block);
    fclose($fh);
}

/* ---------------------- LAST BLOCK HASH --------------------- */

function get_last_block_hash($fh): string {
    fseek($fh, 0, SEEK_SET);

    $lastHash = str_repeat("\x00", 32);

    while (true) {
        $pos = ftell($fh);
        $magic = fread($fh, 6);

        if ($magic === false || strlen($magic) === 0) {
            break; // конец файла
        }
        if ($magic !== "NOVIJ1") {
            // повреждённый блок => прекращаем
            break;
        }

        $LENraw = fread($fh, 4);
        if ($LENraw === false || strlen($LENraw) !== 4) {
            break; // обрыв
        }

        $LEN = unpack('N', $LENraw)[1];
        $body = fread($fh, $LEN);
        if ($body === false || strlen($body) !== $LEN) {
            break; // обрыв
        }

        $hash = fread($fh, 32);
        if ($hash === false || strlen($hash) !== 32) {
            break; // обрыв
        }

        // если дошли сюда — блок корректный
        $lastHash = $hash;
    }

    return $lastHash;
}

/* ============================================================
 *  read [--from OFFSET] [--limit K] [--hex]
 * ============================================================ */
function cmd_read(array $argv): void {
    $from = 0;
    $limit = PHP_INT_MAX;
    $addHex = in_array('--hex', $argv, true);

    for ($i = 0; $i < count($argv); $i++) {
        if ($argv[$i] === '--from' && isset($argv[$i+1])) {
            $from = (int)$argv[$i+1];
        }
        if ($argv[$i] === '--limit' && isset($argv[$i+1])) {
            $limit = (int)$argv[$i+1];
        }
    }

    $fh = fopen('data.npt', 'rb');
    if (!$fh) {
        fwrite(STDERR, "Не открыть data.npt\n");
        exit(1);
    }

    fseek($fh, $from);

    $count = 0;

    while (!feof($fh) && $count < $limit) {
        $pos = ftell($fh);
        $magic = fread($fh, 6);
        if ($magic === false || strlen($magic) === 0) break;

        if ($magic !== "NOVIJ1") {
            fwrite(STDERR, "Ошибка: MAGIC mismatch @ offset $pos\n");
            break;
        }

        $LENraw = fread($fh, 4);
        if ($LENraw === false || strlen($LENraw) !== 4) break;

        $LEN = unpack('N', $LENraw)[1];

        $rest = fread($fh, $LEN);
        if ($rest === false || strlen($rest) !== $LEN) {
            fwrite(STDERR, "Ошибка: повреждён блок @ offset $pos\n");
            break;
        }

        // Разбор внутрянки
        $cursor = 0;

        $ts = unpack('J', substr($rest, $cursor, 8))[1];
        $cursor += 8;

        $prev = substr($rest, $cursor, 32);
        $cursor += 32;

        $plen = unpack('N', substr($rest, $cursor, 4))[1];
        $cursor += 4;

        $payload = substr($rest, $cursor, $plen);
        $cursor += $plen;

        $pub = substr($rest, $cursor, 32);
        $cursor += 32;

        $sig = substr($rest, $cursor, 64);
        $cursor += 64;

        // HASH идёт сразу после SIG (но он вне LEN, поэтому читаем отдельно)
        $hash = fread($fh, 32);
        if ($hash === false || strlen($hash) !== 32) {
            fwrite(STDERR, "Ошибка: плохой HASH @ offset $pos\n");
            break;
        }

        $out = [
            'offset' => $pos,
            'ts'     => $ts,
            'payload'=> json_decode($payload, true),
            'pub'    => bin2hex($pub),
        ];

        if ($addHex) {
            $out['hash'] = bin2hex($hash);
            $out['prev'] = bin2hex($prev);
        }

        echo json_encode($out, JSON_UNESCAPED_SLASHES) . "\n";

        $count++;
    }

    fclose($fh);
}

/* ============================================================
 *  verify — полный проход по всему файлу
 * ============================================================ */
function cmd_verify(): void {
    if (!file_exists('allowlist.json')) {
        fwrite(STDERR, "Нет allowlist.json — выполните init.\n");
        exit(1);
    }
    $allow = json_decode(file_get_contents('allowlist.json'), true);

    $fh = fopen('data.npt', 'rb');
    if (!$fh) {
        fwrite(STDERR, "Не открыть data.npt\n");
        exit(1);
    }

    $expectedPrev = str_repeat("\x00", 32);
    $offset = 0;
    $index = 0;

    while (true) {
        $pos = ftell($fh);
        $block = read_one_block_and_advance($fh);
        if ($block === null) break; // окончен файл
        if (isset($block['error'])) {
    fwrite(STDERR, "Ошибка структуры @ offset {$block['offset']}: {$block['error']}\n");
    exit(1);
}

        // 1) MAGIC проверен внутри read_one_block
        // 2) LEN проверен внутри read_one_block

        // 3) Проверка PREV:
        if ($block['prev'] !== $expectedPrev) {
            fwrite(STDERR, "Ошибка PREV @ offset $pos (block $index)\n");
            fwrite(STDERR, "Ожидалось: ".bin2hex($expectedPrev)."\n");
            fwrite(STDERR, "Получено: ".bin2hex($block['prev'])."\n");
            exit(1);
        }

        // 4) Проверка подписи
        $toSign = hash('sha256', $block['ts_raw'] . $block['prev'] . $block['payload_raw'], true);
        if (!sodium_crypto_sign_verify_detached($block['sig'], $toSign, $block['pub'])) {
            fwrite(STDERR, "Ошибка SIG @ offset $pos (block $index)\n");
            exit(1);
        }

        // 5) Проверка allowlist
        if (!in_array(bin2hex($block['pub']), $allow, true)) {
            fwrite(STDERR, "Ошибка: ключ ".bin2hex($block['pub'])." не в allowlist @ block $index\n");
            exit(1);
        }

        // 6) Проверка HASH
        $calcHash = hash('sha256', $block['LEN_raw'] . $block['body_raw'], true);
        if ($calcHash !== $block['hash']) {
            fwrite(STDERR, "Ошибка HASH @ offset $pos (block $index)\n");
            exit(1);
        }

        // Формируем expectedPrev для следующего блока
        $expectedPrev = $block['hash'];
        $index++;
    }

    fclose($fh);
    fwrite(STDOUT, "OK: проверено блоков = $index\n");
}

/* ============================================================
 *  export — экспорт всего лога в NDJSON
 * ============================================================ */
function cmd_export(): void {
    $fh = fopen('data.npt', 'rb');
    if (!$fh) {
        fwrite(STDERR, "Не открыть data.npt\n");
        exit(1);
    }

    while (true) {
        $block = read_one_block_and_advance($fh);
        if ($block === null) break;

if (isset($block['error'])) {
    // тихо прекращаем чтение
    break;
}

        $out = [
            'offset'  => $block['offset'],
            'ts'      => $block['ts'],
            'payload' => $block['payload'],
            'pub'     => bin2hex($block['pub']),
            'hash'    => bin2hex($block['hash']),
            'prev'    => bin2hex($block['prev']),
        ];

        echo json_encode($out, JSON_UNESCAPED_SLASHES) . "\n";
    }

    fclose($fh);
}
/* ============================================================
 *  search — фильтрация блоков
 * ============================================================ */
function cmd_search(array $argv): void {
    $q = null;          // substring
    $fieldKey = null;   // key
    $fieldValue = null; // value (строка/число/bool)
    $since = null;
    $until = null;
    $pubFilter = null;  // hex

    // --- разбор аргументов ---
    for ($i = 0; $i < count($argv); $i++) {

        if ($argv[$i] === '--q' && isset($argv[$i+1])) {
            $q = $argv[$i+1];
        }

        if ($argv[$i] === '--field' && isset($argv[$i+1])) {
            $pair = $argv[$i+1];
            $eqPos = strpos($pair, '=');
            if ($eqPos === false) {
                fwrite(STDERR, "Ошибка: --field key=value\n");
                exit(1);
            }
            $fieldKey = substr($pair, 0, $eqPos);
            $rawVal = substr($pair, $eqPos + 1);

            // auto‑type: число, true/false, строка
            if (is_numeric($rawVal)) {
                $fieldValue = $rawVal + 0;
            } elseif ($rawVal === 'true') {
                $fieldValue = true;
            } elseif ($rawVal === 'false') {
                $fieldValue = false;
            } else {
                $fieldValue = $rawVal;
            }
        }

        if ($argv[$i] === '--since' && isset($argv[$i+1])) {
            $since = (int)$argv[$i+1];
        }

        if ($argv[$i] === '--until' && isset($argv[$i+1])) {
            $until = (int)$argv[$i+1];
        }

        if ($argv[$i] === '--pub' && isset($argv[$i+1])) {
            $pubFilter = strtolower($argv[$i+1]);
        }
    }

    $fh = fopen('data.npt', 'rb');
    if (!$fh) {
        fwrite(STDERR, "Не открыть data.npt\n");
        exit(1);
    }

    while (true) {
        $block = read_one_block_and_advance($fh);
        if ($block === null) break;

if (isset($block['error'])) {
    // тихо прекращаем чтение
    break;
}

        $jsonRaw = $block['payload_raw'];
        $pubHex  = bin2hex($block['pub']);
        $ts      = $block['ts'];
        $payload = $block['payload'];

        // --- фильтры ---
        // substring
        if ($q !== null && strpos($jsonRaw, $q) === false) {
            continue;
        }

        // field filter
        if ($fieldKey !== null) {
            if (!array_key_exists($fieldKey, $payload)) {
                continue;
            }
            if ($payload[$fieldKey] !== $fieldValue) {
                continue;
            }
        }

        // time filters
        if ($since !== null && $ts < $since) continue;
        if ($until !== null && $ts > $until) continue;

        // pub filter
        if ($pubFilter !== null && strtolower($pubHex) !== $pubFilter) continue;

        // --- вывод результата ---
        $out = [
            'offset'  => $block['offset'],
            'ts'      => $ts,
            'payload' => $payload,
            'pub'     => $pubHex,
        ];

        echo json_encode($out, JSON_UNESCAPED_SLASHES) . "\n";
    }

    fclose($fh);
}
?>