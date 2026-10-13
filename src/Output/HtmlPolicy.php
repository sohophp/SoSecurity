<?php
declare(strict_types=1);
namespace SoSecurity\Output;
use SoSecurity\Exception\ConfigurationException;
final class HtmlPolicy
{
    private $options;
    public function __construct(array $options=[])
    {
        $defaults=['maximum_input'=>65536,'maximum_output'=>131072,'maximum_nodes'=>2048,'maximum_depth'=>64,'maximum_attribute'=>2048,'allow_links'=>true];
        if (array_diff(array_keys($options),array_keys($defaults))) { throw new ConfigurationException('Unknown HTML cleaning option.','configuration.html'); }
        $options+=$defaults;
        foreach (['maximum_input'=>[1,1048576],'maximum_output'=>[1,2097152],'maximum_nodes'=>[16,8192],'maximum_depth'=>[8,128],'maximum_attribute'=>[64,4096]] as $name=>$range) {
            if (!is_int($options[$name]) || $options[$name]<$range[0] || $options[$name]>$range[1]) { throw new ConfigurationException('Invalid HTML resource budget.','configuration.html'); }
        }
        if (!is_bool($options['allow_links'])) { throw new ConfigurationException('HTML link choice must be bool.','configuration.html'); }
        $this->options=[]; foreach ($options as $name=>$value) { $this->options[$name]=$value; }
    }
    public function options(): array { return $this->options; }
}
