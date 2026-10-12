# 输入验证

`Validator` 严格检查输入并返回稳定错误代码，不要求框架、语言包或mbstring。它不会删除HTML、转义SQL、自动授权或把字符串悄悄转换为整数。输入验证与输出编码、参数化SQL是各自的边界，参考 [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)。

## 最小完整调用

```php
require 'vendor/autoload.php';
$validator = new SoSecurity\Validation\Validator([
    'profile' => ['type' => 'object', 'fields' => [
        'name' => ['type' => 'string', 'min' => 2, 'max' => 20],
        'age' => ['type' => 'integer', 'min' => 18, 'max' => 120],
        'email' => ['type' => 'string', 'format' => 'email'],
        'kind' => ['type' => 'string', 'enum' => ['member', 'guest']],
    ]],
    'tags' => ['type' => 'list', 'max' => 8, 'items' => ['type' => 'string', 'max' => 30]],
]);
$result = $validator->validate($inputArray);
if (!$result->valid()) {
    $errors = $result->errors(); // 例如 /profile/age + validation.type
    // 宿主响应422、把code映射为本地化提示；不要记录被拒绝的密码/令牌原文。
    return;
}
$data = $result->data(); // 仅完整验证成功才允许读取
```

校验失败时data()抛 `ValidationException(validation.invalid)`，不提供部分成功字段供业务误用。返回错误是JSON Pointer路径与code，不含被拒绝的值；列表项例如 `/tags/0`。字段名中的`~`与`/`按Pointer编码。返回字段路径用于定位，展示时仍需HTML编码。

## 规则与默认值

| 选项 | 默认/适用 | 行为 |
| --- | --- | --- |
| type | 必填 | string/integer/number/boolean/object/list，严格类型；number接收有限整数或浮点数 |
| required | true | 字段不存在时报required；false允许省略，不填充默认值 |
| nullable | false | true明确允许null，null直接通过该字段且不调用其他规则 |
| min/max | 未配置 | 数值范围、字符串Unicode码点长度或列表元素数；边界包含 |
| enum | 未配置 | 1–128个有界标量，使用严格类型比较；在NFC后比较 |
| maximum_bytes | string默认65536 | 1–65536字节，在规范化前后检查 |
| format | string可选 | email、uuid、date（真实YYYY-MM-DD日历日期）、ascii_identifier |
| pattern | string可选 | 可信配置提供的PCRE，最长1024字节；必须匹配整个输入 |
| normalization | string默认none | 只有显式NFC才调用ext-intl；缺扩展时报DependencyException，不静默跳过 |
| fields | object必填 | 嵌套字段定义，每层拒绝未知字段 |
| items | list必填 | 每个元素的定义；列表键必须是从0开始的连续整数 |
| rules | 最多16项 | 应用提供Rule对象；只能来自可信代码，不能从用户请求加载 |

配置拼错、错误类型、反向区间、非法正则或结构超限在构造时抛ConfigurationException。schema编译时复制数组，不受外部引用后续修改影响。自定义Rule对象由应用管理，应保持不变。

字符串必须是合法UTF-8；长度为Unicode码点，组合字符与emoji序列可能包含多个码点，**不是用户感知的字形簇**。默认不规范化、不trim、不截断；需要NFC时，存储和比较必须使用同一规范化策略。自由文本可以包含引号、换行与HTML字符，使用时按上下文编码。email采用PHP FILTER_VALIDATE_EMAIL，不承诺验证域名、邮箱存在、国际化邮件地址或投递能力。uuid仅检查标准结构、版本1–8和variant，不证明来源可信。

传统表单的值通常是字符串。宿主先按字段定义明确解析（例如filter_var验证整数且严格区分false与0），再验证；不要对所有字段强制 `(int)` 后声称类型已正确。JSON也应先检查解析成功、请求体限额和预期结构，再调用Validator。

## 自定义规则与故障

```php
final class ReservedName implements SoSecurity\Validation\Rule
{
    public function code(): string { return 'reserved_name'; }
    public function passes($value): bool { return !in_array($value, ['admin', 'root'], true); }
}
$validator = new SoSecurity\Validation\Validator([
    'name' => ['type' => 'string', 'rules' => [new ReservedName()]],
]);
```

拒绝返回 `validation.custom.reserved_name`。规则抛异常则包装为 `SecurityException(validation.rule_failure)`，不能当作通过；展示稳定原因，不展示底层异常全文。规则需要有界、无外部I/O和状态修改，库无法抢占任意用户代码或一个过慢的正则。正则由可信开发者配置，限制输入长度并审核回溯复杂度；PCRE执行错误按pattern拒绝。

## 资源限制与演示

整个输入默认预算262144字节，构造第二参数可设1–1048576。遍历先检查最大16层、4096节点、每数组最多256项、单字符串65536字节及字段键最长128字节/UTF-8；对象、资源、循环引用或超预算返回根路径 `validation.resources`。该字节预算计算字符串和字段键字节，标量计16字节，是遍历预算而非PHP进程内存的精确测量。请求进入库之前的HTTP解析/JSON解码仍由宿主限制。

schema最多12层、256条字段/元素定义，每对象最多128字段。库接收PHP数组；空列表与空对象在PHP数组中不能区分，字段定义决定语义。

演示：[输入验证](http://72.rocky.wsl/SoSecurity/?module=validation)，含正常、错误类型/格式、未知字段、嵌套定位和可编辑JSON，传统表单与AJAX均调用真实Validator。测试见 `tests/validation.php`；例子见 `examples/input-validation.php`。
