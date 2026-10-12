<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;

use SoSecurity\Exception\DependencyException;
use SoSecurity\Http\Uri;
use SoSecurity\Http\RequestException;
use SoSecurity\Support\Deadline;

final class CurlTransport implements Transport
{
    public function __construct()
    {
        if (!extension_loaded('curl') || curl_version()['version_number'] < 0x073900) { throw new DependencyException('Pinned requests require ext-curl/libcurl 7.57 or newer.', 'dependency.curl'); }
    }
    public function send(Uri $uri, string $pinnedIp, string $method, array $headers, string $body, Deadline $deadline, int $maximumBody, int $maximumHeaders): Response
    {
        $headers = RequestHeaders::normalize($headers);
        if (!in_array($method, ['GET','HEAD','POST'], true) || ($method !== 'POST' && $body !== '') || strlen($body) > 1048576
            || $maximumBody < 0 || $maximumBody > 20971520 || $maximumHeaders < 0 || $maximumHeaders > 65536) {
            throw new \SoSecurity\Exception\ValidationException('Invalid transport request/budgets.', 'http.request');
        }
        if (!PublicAddress::allows($pinnedIp)) { throw new RequestException('Pinned address is not public.', 'http.address'); }
        if ((filter_var($uri->hostName(), FILTER_VALIDATE_IP) !== false && @inet_pton($uri->hostName()) !== @inet_pton($pinnedIp))
            || $uri->hostName() === 'localhost' || substr($uri->hostName(), -10) === '.localhost') {
            throw new RequestException('URI literal/special host disagrees with the pin.', 'http.address');
        }
        $remaining = $deadline->remaining();
        if ($remaining <= 0) { throw new RequestException('Request budget expired.', 'http.timeout'); }
        $handle = curl_init();
        if ($handle === false) { throw new RequestException('Cannot initialize request.', 'http.transport'); }
        $responseBody = ''; $responseHeaders = []; $headerBytes = 0; $failure = null; $inHeaders = false;
        try {
            $lines = [];
            foreach ($headers as $name=>$value) { $lines[] = $name . ': ' . $value; }
            $address = strpos($pinnedIp, ':') === false ? $pinnedIp : '[' . $pinnedIp . ']';
            $options = [CURLOPT_URL=>$uri->withoutFragment()->url(), CURLOPT_FOLLOWLOCATION=>false, CURLOPT_MAXREDIRS=>0,
                CURLOPT_PROTOCOLS=>CURLPROTO_HTTP | CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS=>CURLPROTO_HTTP | CURLPROTO_HTTPS,
                CURLOPT_PROXY=>'', CURLOPT_NOPROXY=>'*', CURLOPT_NETRC=>false, CURLOPT_UNRESTRICTED_AUTH=>false,
                CURLOPT_RESOLVE=>[$uri->hostName() . ':' . $uri->port() . ':' . $address], CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_SSL_VERIFYHOST=>2,
                CURLOPT_SSLVERSION=>CURL_SSLVERSION_TLSv1_2, CURLOPT_HTTP_VERSION=>CURL_HTTP_VERSION_1_1, CURLOPT_PATH_AS_IS=>true,
                CURLOPT_NOSIGNAL=>true, CURLOPT_CONNECTTIMEOUT_MS=>max(1, min(1000, (int) ceil($remaining * 1000))),
                CURLOPT_TIMEOUT_MS=>max(1, (int) ceil($remaining * 1000)), CURLOPT_USERAGENT=>'SoSecurity restricted client',
                CURLOPT_HTTPHEADER=>$lines, CURLOPT_ACCEPT_ENCODING=>'identity', CURLOPT_HEADER=>false, CURLOPT_RETURNTRANSFER=>false,
                CURLOPT_CUSTOMREQUEST=>$method, CURLOPT_NOBODY=>$method === 'HEAD', CURLOPT_NOPROGRESS=>false];
            if ($method === 'POST') { $options[CURLOPT_POSTFIELDS] = $body; }
            $options[CURLOPT_PROGRESSFUNCTION] = function () use ($deadline, &$failure) { if ($deadline->remaining() <= 0) { $failure = 'http.timeout'; return 1; } return 0; };
            $options[CURLOPT_WRITEFUNCTION] = function ($unused, string $chunk) use (&$responseBody, &$failure, $maximumBody, $deadline) {
                if ($deadline->remaining() <= 0) { $failure = 'http.timeout'; return 0; }
                if (strlen($responseBody) + strlen($chunk) > $maximumBody) { $failure = 'http.response_limit'; return 0; }
                $responseBody .= $chunk; return strlen($chunk);
            };
            $options[CURLOPT_HEADERFUNCTION] = function ($unused, string $line) use (&$responseHeaders, &$headerBytes, &$failure, &$inHeaders, $maximumHeaders, $deadline) {
                $headerBytes += strlen($line);
                if ($headerBytes > $maximumHeaders || $deadline->remaining() <= 0) { $failure = $headerBytes > $maximumHeaders ? 'http.header_limit' : 'http.timeout'; return 0; }
                $trimmed = rtrim($line, "\r\n");
                if (preg_match('/\AHTTP\/1\.[01] [1-5][0-9]{2}(?: [^\x00-\x1f]*)?\z/D', $trimmed)) { $responseHeaders = []; $inHeaders = true; return strlen($line); }
                if ($trimmed === '') { $inHeaders = false; return strlen($line); }
                if (!$inHeaders) { return strlen($line); } // Never interpret trailers as Location or authorization metadata.
                $colon = strpos($trimmed, ':');
                if ($colon === false || !preg_match('/\A[a-zA-Z0-9!#$%&\x27*+.^_`|~-]+\z/D', substr($trimmed, 0, $colon))) { $failure = 'http.headers'; return 0; }
                $name = strtolower(substr($trimmed, 0, $colon)); $value = trim(substr($trimmed, $colon + 1), " \t");
                if (preg_match('/[\x00-\x08\x0a-\x1f\x7f]/', $value)) { $failure = 'http.headers'; return 0; }
                $responseHeaders[$name][] = $value; return strlen($line);
            };
            if (!curl_setopt_array($handle, $options)) { throw new RequestException('Cannot enforce transport restrictions.', 'http.configuration'); }
            $ok = curl_exec($handle); $errno = curl_errno($handle);
            if ($failure !== null || $ok === false || $deadline->remaining() <= 0) {
                throw new RequestException('Restricted transport failed.', $failure ?? ($errno === CURLE_OPERATION_TIMEDOUT || $deadline->remaining() <= 0 ? 'http.timeout' : 'http.transport'));
            }
            $peer = curl_getinfo($handle, CURLINFO_PRIMARY_IP);
            if (@inet_pton($peer) !== @inet_pton($pinnedIp)) { throw new RequestException('Connection does not match its pin.', 'http.peer'); }
            return new Response((int) curl_getinfo($handle, CURLINFO_HTTP_CODE), $responseHeaders, $responseBody, $peer, $headerBytes);
        } finally { if (is_resource($handle)) { curl_close($handle); } }
    }
}
