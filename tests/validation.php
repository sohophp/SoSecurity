<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Validation\Validator;
use SoSecurity\Validation\Rule;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;

$schema = ['profile' => ['type' => 'object', 'fields' => [
    'name' => ['type' => 'string', 'min' => 2, 'max' => 5],
    'age' => ['type' => 'integer', 'min' => 18, 'max' => 120],
    'email' => ['type' => 'string', 'format' => 'email'],
    'kind' => ['type' => 'string', 'enum' => ['member', 'guest']],
]], 'tags' => ['type' => 'list', 'max' => 2, 'items' => ['type' => 'string', 'format' => 'ascii_identifier']],
    'opt' => ['type' => 'boolean', 'required' => false, 'nullable' => true]];
$validator = new Validator($schema);
$input = ['profile' => ['name' => '张小明', 'age' => 20, 'email' => 'a@example.test', 'kind' => 'member'], 'tags' => ['hello']];
Check::same(true, $validator->validate($input)->valid()); Check::same($input, $validator->validate($input)->data());
$bad = $input; $bad['profile']['age'] = '20'; $bad['profile']['email'] = 'bad'; $bad['tags'] = ['a', 'b', 'c'];
$result = $validator->validate($bad);
Check::same(false, $result->valid());
Check::same([['path' => '/profile/age', 'code' => 'validation.type'], ['path' => '/profile/email', 'code' => 'validation.format'],
    ['path' => '/tags', 'code' => 'validation.max']], $result->errors());
Check::throws(ValidationException::class, function () use ($result) { $result->data(); });
$bad = $input; unset($bad['profile']['age']); $bad['profile']['name'] = '中'; $bad['profile']['kind'] = 'ADMIN';
Check::same(['validation.min', 'validation.required', 'validation.enum'], array_column($validator->validate($bad)->errors(), 'code'));
$bad = $input; $bad['profile']['name'] = "\xff";
Check::same('validation.utf8', $validator->validate($bad)->errors()[0]['code']);
$bad = $input; $bad['profile']['extra'] = '<script>'; $bad['weird~/key'] = 'secret';
Check::same('/weird~0~1key', $validator->validate($bad)->errors()[0]['path']);
Check::same('/profile/extra', $validator->validate($bad)->errors()[1]['path']);
Check::same(false, strpos(json_encode($validator->validate($bad)->errors()), 'secret') !== false);
$bad = $input; $bad['tags'] = [1 => 'hello'];
Check::same('validation.type', $validator->validate($bad)->errors()[0]['code']);
$bad = $input; $bad['opt'] = null; Check::same(true, $validator->validate($bad)->valid());
$bad['opt'] = 1; Check::same(false, $validator->validate($bad)->valid());
$only = new Validator(['n' => ['type' => 'number', 'min' => -1, 'max' => 2.5]]);
Check::same(true, $only->validate(['n' => 2.5])->valid()); Check::same(false, $only->validate(['n' => INF])->valid());
Check::same(false, $only->validate(['n' => NAN])->valid()); Check::same(false, $only->validate(['n' => true])->valid());
$text = new Validator(['v' => ['type' => 'string', 'max' => 2, 'maximum_bytes' => 6]]);
Check::same(true, $text->validate(['v' => '中文'])->valid()); Check::same(false, $text->validate(['v' => '中文三'])->valid());
Check::same(true, $text->validate(['v' => "a\n"])->valid());
Check::same(false, (new Validator(['v' => ['type' => 'string']], 8))->validate(['v' => '12345678'])->valid());
$cycle = []; $cycle['loop'] =& $cycle;
Check::same('validation.resources', $validator->validate($cycle)->errors()[0]['code']);
Check::same('validation.resources', $validator->validate(['x' => new stdClass()])->errors()[0]['code']);
Check::same('validation.resources', $validator->validate(array_fill(0, 257, 1))->errors()[0]['code']);
Check::same('validation.resources', $validator->validate(['x' => str_repeat('a', 65537)])->errors()[0]['code']);
$rule = new class implements Rule { public function passes($v): bool { return $v !== 'admin'; } public function code(): string { return 'reserved'; } };
$custom = new Validator(['name' => ['type' => 'string', 'rules' => [$rule]]]);
Check::same('validation.custom.reserved', $custom->validate(['name' => 'admin'])->errors()[0]['code']);
Check::same(true, $custom->validate(['name' => 'member'])->valid());
$crash = new class implements Rule { public function passes($v): bool { throw new RuntimeException('private error'); } public function code(): string { return 'crash'; } };
Check::throws(SecurityException::class, function () use ($crash) { (new Validator(['v' => ['type' => 'string', 'rules' => [$crash]]]))->validate(['v' => 'a']); });
$pattern = new Validator(['v' => ['type' => 'string', 'pattern' => '/[A-Z]+/D']]);
Check::same(true, $pattern->validate(['v' => 'ABC'])->valid()); Check::same(false, $pattern->validate(['v' => 'aABC'])->valid());
foreach ([['type' => 'integer', 'min' => '1'], ['type' => 'string', 'max' => -1], ['type' => 'string', 'min' => 5, 'max' => 4],
    ['type' => 'string', 'pattern' => '/[/'], ['type' => 'string', 'format' => 'html'], ['type' => 'boolean', 'max' => 1],
    ['type' => 'object'], ['type' => 'list'], ['type' => 'string', 'required' => 'true'], ['type' => 'string', 'enum' => [new stdClass()]], ['type' => 'string', 'maximum_bytes' => null], ['type' => 'string', 'normalization' => null]] as $spec) {
    Check::throws(ConfigurationException::class, function () use ($spec) { new Validator(['v' => $spec]); });
}
$enum = ['yes']; $definition = ['v' => ['type' => 'string', 'enum' => &$enum]]; $frozen = new Validator($definition); $enum[] = 'admin';
Check::same(false, $frozen->validate(['v' => 'admin'])->valid());
$validData = $validator->validate($input)->data(); $validData['profile']['age'] = 1;
Check::same(20, $validator->validate($input)->data()['profile']['age']);
foreach (['email' => ['a@example.test', 'a@'], 'date' => ['2024-02-29', '2025-02-29'],
    'uuid' => ['550e8400-e29b-41d4-a716-446655440000', 'x']] as $format => $values) {
    $v = new Validator(['v' => ['type' => 'string', 'format' => $format]]);
    Check::same(true, $v->validate(['v' => $values[0]])->valid()); Check::same(false, $v->validate(['v' => $values[1]])->valid());
}
if (extension_loaded('intl')) {
    $nfc = new Validator(['v' => ['type' => 'string', 'normalization' => 'NFC', 'max' => 1]]);
    Check::same("\xc3\xa9", $nfc->validate(['v' => "e\xcc\x81"])->data()['v']);
} else {
    Check::throws(DependencyException::class, function () { new Validator(['v' => ['type' => 'string', 'normalization' => 'NFC']]); });
}
require dirname(__DIR__) . '/examples/input-validation.php';
Check::same(true, SoSecurity\Examples\validateProfile(['profile' => ['name' => '张小明', 'age' => 20, 'email' => 'a@example.test']])->valid());
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " validation assertions passed\n";
