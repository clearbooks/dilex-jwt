<?php

declare(strict_types=1);

namespace Clearbooks\Dilex\JwtGuard;

use ArrayAccess;
use DateTime;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;
use Symfony\Component\HttpFoundation\Request;

use function in_array;
use function is_array;
use function array_map;
use function str_starts_with;
use function trim;
use function substr;
use function strlen;

class JwtTokenAuthenticator implements RequestAuthoriser, IdentityProvider
{
    protected const string USER_ID = 'userId';
    protected const string GROUP_ID = 'groupId';
    protected const string APP_ID = 'appId';
    protected const string EXPIRY = 'exp';
    protected const string IS_ADMIN = 'isAdmin';
    protected const string SEGMENTS = 'segments';
    protected const string BEARER = 'Bearer ';

    protected stdClass $token;

    public function __construct(
        #[\SensitiveParameter] protected readonly Key|ArrayAccess|array $key,
        protected readonly AppIdProvider $appIdProvider
    ) {
        $this->token = new stdClass;
    }

    protected function getClaimOrNull( string $claim ): mixed
    {
        return $this->token->$claim ?? null;
    }

    protected function isExpired(): bool
    {
        $exp = \DateTime::createFromFormat( 'U', $this->getClaimOrNull( self::EXPIRY ) );
        return !$exp || $exp <= ( new DateTime );
    }

    protected function hasUserId(): bool
    {
        return (bool)$this->getClaimOrNull( self::USER_ID );
    }

    protected function isAllowedAppId(): bool
    {
        return in_array( $this->getClaimOrNull( self::APP_ID ), $this->appIdProvider->getAppIds(), true );
    }

    #[\Override]
    public function isAuthorised( Request $request ): bool
    {
        $header = $request->headers->get( 'Authorization' );

        if ($header === null) {
            return false;
        }

        try{
            $this->token = JWT::decode( $this->extractJwtFromHeader($header), $this->key );
        } catch ( \Exception ){
            return false;
        }

        return !($this->isExpired() || !$this->hasUserId() || !$this->isAllowedAppId());
    }

    #[\Override]
    public function getUserId(): mixed
    {
        return $this->getClaimOrNull( self::USER_ID );
    }

    #[\Override]
    public function getGroupId(): mixed
    {
        return $this->getClaimOrNull( self::GROUP_ID );
    }

    #[\Override]
    public function getIsAdmin(): bool
    {
        return (bool)$this->getClaimOrNull( self::IS_ADMIN );
    }

    #[\Override]
    public function getSegments(): array
    {
        $segments = $this->getClaimOrNull( self::SEGMENTS );

        if (!is_array($segments)) {
            return [];
        }

        return array_map(
            static function (stdClass $segment): array {
                return (array) $segment;
            },
            $segments
        );
    }

    protected function extractJwtFromHeader( #[\SensitiveParameter] string $header )
    {
        if (str_starts_with($header, self::BEARER)) {
            return trim(substr( $header, strlen( self::BEARER ) ));
        }
        return $header;
    }
}
