<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;

use SoSecurity\Exception\ValidationException;
use SoSecurity\Http\Uri;
use SoSecurity\Http\RequestException;
use SoSecurity\Support\Deadline;

final class Client
{
    private $policy;
    private $resolver;
    private $transport;
    public function __construct(Policy $policy, ?Resolver $resolver = null, ?Transport $transport = null)
    {
        $this->policy = $policy; $this->transport = $transport ?? new CurlTransport(); $this->resolver = $resolver ?? new DohResolver();
    }
    public function request(string $method, string $url, array $headers = [], string $body = ''): Response
    {
        if (!in_array($method, ['GET','HEAD','POST'], true) || ($method !== 'POST' && $body !== '') || strlen($body) > $this->policy->requestBytes()) {
            throw new ValidationException('Request method/body is not accepted.', 'http.request');
        }
        $headers = RequestHeaders::normalize($headers); $uri = Uri::parse($url); $seen = [];
        $deadline = new Deadline($this->policy->budgetMs()); $bodyRemaining = $this->policy->responseBytes(); $headersRemaining = $this->policy->headerBytes();
        for ($hop = 0; ; ++$hop) {
            $this->budget($deadline); $this->policy->check($uri);
            if (isset($seen[$uri->url()])) { throw new RequestException('Redirect loop detected.', 'http.redirect_loop'); }
            $seen[$uri->url()] = true;
            $addresses = filter_var($uri->hostName(), FILTER_VALIDATE_IP) !== false ? [$uri->hostName()] : $this->resolver->resolve($uri->hostName(), $deadline);
            $this->budget($deadline);
            if (!$addresses || count($addresses) > 16) { throw new RequestException('DNS address set is invalid.', 'http.dns'); }
            foreach ($addresses as $address) { if (!is_string($address) || !PublicAddress::allows($address)) { throw new ValidationException('Resolved address set contains a non-public target.', 'http.address'); } }
            $addresses = array_values($addresses); $pin = $addresses[0];
            $response = $this->transport->send($uri, $pin, $method, $headers, $body, $deadline, $bodyRemaining, $headersRemaining);
            $this->budget($deadline);
            if (@inet_pton($response->peer()) !== @inet_pton($pin)) { throw new RequestException('Transport peer does not match its pin.', 'http.peer'); }
            $bodyRemaining -= strlen($response->body()); $headersRemaining -= $response->headerBytes();
            if ($bodyRemaining < 0 || $headersRemaining < 0) { throw new RequestException('Aggregate response budget exceeded.', $bodyRemaining < 0 ? 'http.response_limit' : 'http.header_limit'); }
            if (!in_array($response->status(), [301,302,303,307,308], true)) { return $response; }
            $locations = $response->values('location');
            if (count($locations) !== 1 || $locations[0] === '') { throw new RequestException('Redirect needs one unambiguous Location.', 'http.redirect'); }
            if ($method === 'POST') { throw new RequestException('State-changing requests are never automatically replayed.', 'http.redirect_method'); }
            if ($hop >= $this->policy->redirects()) { throw new RequestException('Redirect count exceeded.', 'http.redirect_limit'); }
            if ($headersRemaining === 0) { throw new RequestException('No header budget remains for another hop.', 'http.header_limit'); }
            $next = $uri->resolve($locations[0])->withoutFragment();
            if ($next->scheme() !== $uri->scheme() && $uri->scheme() === 'https') { throw new ValidationException('HTTPS downgrade is forbidden.', 'http.downgrade'); }
            if ($next->origin() !== $uri->origin()) { $headers = []; } // No application headers or credentials forwarded across origins.
            $uri = $next;
        }
    }
    private function budget(Deadline $deadline): void { if ($deadline->remaining() <= 0) { throw new RequestException('Overall request budget expired.', 'http.timeout'); } }
}
