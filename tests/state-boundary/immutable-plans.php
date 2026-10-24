<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
$digest=str_repeat('a',64);
$cases=[
    'StateRetirementReview'=>['purpose'=>'retire_unknown','context'=>$digest,'revision'=>2,'operation'=>$digest,'before'=>$digest,'observed'=>$digest,'intent'=>$digest,'control'=>$digest,'issued'=>100,'expires'=>200,'nonce'=>$digest,'key'=>'test','seal'=>$digest],
    'StateSuccessorReview'=>['purpose'=>'stage_successor','context'=>$digest,'revision'=>2,'predecessor'=>$digest,'observed'=>$digest,'intent'=>$digest,'control'=>$digest,'generation'=>$digest,'issued'=>100,'expires'=>200,'nonce'=>$digest,'key'=>'test','seal'=>$digest],
];
foreach(['StateContainmentReview'=>'contain_accounts','StateFactorContainmentReview'=>'contain_factors','StateFactorResolutionReview'=>'resolve_factors'] as $class=>$purpose){
    $cases[$class]=['purpose'=>$purpose,'context'=>$digest,'generation'=>$digest,'revision'=>3,'sequence'=>1,'authority'=>$digest,'observed'=>$digest,'plan'=>$digest,'count'=>1,'control'=>$digest,'issued'=>100,'expires'=>200,'nonce'=>$digest,'key'=>'test','seal'=>$digest];
}
foreach($cases as $class=>$data){
    $nonce=$digest;$issued=100;$data['nonce']=&$nonce;$data['issued']=&$issued;$name='SoSecurity\\Account\\'.$class;
    $review=new $name($data);$fingerprint=$review->fingerprint();$nonce=str_repeat('b',64);$issued=-1;
    Check::same($digest,$review->metadata()['nonce']);Check::same(100,$review->metadata()['issued']);Check::same($fingerprint,$review->fingerprint());
    unset($data['nonce'],$data['issued']);
}
managedCase(static function(ManagedEnvironment $e):void{
    $x=new EntryEnvironment($e,true);$witness=new SoSecurity\Account\LocalStateWitness($e->pdo,$e->directory.'/independent-witness','managed-test','tenant',str_repeat('e',64),$e->keys,$x->source,static function():bool{return false;},30000,3,str_repeat('c',64));
    $fields=['scope','subject','credential_version','address_version','address','password','status','verified','mfa_required','roles'];$columns=array_combine($fields,$fields);$passwordColumn='password';$columns['password']=&$passwordColumn;
    $plan=new SoSecurity\Account\StateAccountContainment($witness,$x->source,$x->sources['sql'],'complete-sql','account_example',$columns,'tenant',['user']);
    $before=$plan->observed();$passwordColumn='subject';Check::same($before,$plan->observed());Check::same($before,$x->source->digest());Check::same('current',$x->inspect()['status']);
});
echo 'PASS immutable sealed selections: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; caller-held references cannot change reviewed nonces, times or fingerprints',PHP_EOL;
