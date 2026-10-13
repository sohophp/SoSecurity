<?php
declare(strict_types=1);
namespace SoSecurity\Output;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\SecurityException;

/** Resource/encoding boundary around a reviewed sanitizer. Preflight DOM is never used as cleaned output. */
final class HtmlCleaner
{
    private $sanitizer;
    private $options;
    public function __construct(HtmlSanitizer $sanitizer,?HtmlPolicy $policy=null)
    {
        if (!extension_loaded('dom')) { throw new DependencyException('HTML resource preflight requires ext-dom.','dependency.dom'); }
        $this->sanitizer=$sanitizer; $this->options=($policy ?? new HtmlPolicy())->options();
    }
    public function clean(string $html): string
    {
        if (strlen($html)>$this->options['maximum_input']) { throw new ValidationException('HTML input exceeds byte budget.','html.input_limit'); }
        if (!preg_match('//u',$html) || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/',$html)) { throw new ValidationException('Use UTF-8 HTML without forbidden controls.','html.encoding'); }
        $this->preflight($html);
        try { $output=$this->sanitizer->sanitize($html); }
        catch (\Throwable $e) { throw new SecurityException('HTML sanitization failed.','html.provider',$e); }
        if (strlen($output)>$this->options['maximum_output'] || !preg_match('//u',$output) || strpos($output,"\0")!==false) {
            throw new SecurityException('HTML sanitizer output violates its budget/encoding contract.','html.output');
        }
        return $output;
    }
    private function preflight(string $html): void
    {
        $document=new \DOMDocument();
        // No DTD/entity expansion or PARSEHUGE flags. Does not switch libxml error mode or the host PHP handler.
        $loaded=$document->loadHTML('<!doctype html><html><head><meta charset="UTF-8"></head><body>'.$html.'</body></html>',LIBXML_NONET|LIBXML_NOERROR|LIBXML_NOWARNING);
        if (!$loaded) { throw new ValidationException('HTML cannot be parsed within the preflight boundary.','html.parse'); }
        $pending=[[$document,0]]; $count=1;
        while ($pending) {
            list($node,$depth)=array_pop($pending);
            if ($depth>$this->options['maximum_depth']) { throw new ValidationException('HTML tree exceeds depth budget.','html.tree_limit'); }
            if ($node instanceof \DOMElement) {
                foreach ($node->attributes as $attribute) {
                    if (++$count>$this->options['maximum_nodes'] || strlen($attribute->value)>$this->options['maximum_attribute']) { throw new ValidationException('HTML attributes exceed budget.','html.attribute_limit'); }
                }
            }
            if ($node->hasChildNodes()) {
                foreach ($node->childNodes as $child) {
                    if (++$count>$this->options['maximum_nodes']) { throw new ValidationException('HTML tree exceeds node budget.','html.tree_limit'); }
                    $pending[]=[$child,$depth+1];
                }
            }
        }
    }
}
