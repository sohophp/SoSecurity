<?php
declare(strict_types=1);
namespace SoSecurity\Account;
interface MailTransport
{
    /** Stable configured provider name for its shared quota; never a user-selected destination. */
    public function name():string;
    /** One submission only, no automatic retry. Call gate before any content upload; abort if it refuses/throws. */
    public function send(MailMessage $message,int $milliseconds,callable $gate):MailResult;
}
