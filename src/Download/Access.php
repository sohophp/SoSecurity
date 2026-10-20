<?php
declare(strict_types=1);
namespace SoSecurity\Download;

/** Trusted server adapter; it must verify current proof, never a client-provided Account/Decision/Grant. */
interface Access
{
    public function authorize(File $file,Request $request):?Grant;
}
