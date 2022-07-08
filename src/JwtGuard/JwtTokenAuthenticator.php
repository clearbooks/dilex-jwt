<?php
namespace Clearbooks\Dilex\JwtGuard;

use DateTime;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;
use Symfony\Component\HttpFoundation\Request;

class JwtTokenAuthenticator implements RequestAuthoriser, IdentityProvider
{
    const USER_ID = 'userId';
    const GROUP_ID = 'groupId';
    const APP_ID = 'appId';
    const EXPIRY = 'exp';
    const IS_ADMIN = 'isAdmin';
    const SEGMENTS = 'segments';
    const BEARER = 'Bearer ';

    /**
     * @var Key
     */
    protected $key;

    /**
     * @var stdClass
     */
    protected $token;

    /**
     * @var AppIdProvider
     */
    protected $appIdProvider;

    /**
     * @param Key $key
     * @param AppIdProvider $appIdProvider
     */
    public function __construct( Key $key, AppIdProvider $appIdProvider )
    {
        $this->key = $key;
        $this->token = new stdClass;
        $this->appIdProvider = $appIdProvider;
    }

    /**
     * Get a claim if we have one or return null
     * @param string $claim the name of the claim
     * @return mixed
     */
    protected function getClaimOrNull( $claim )
    {
        return $this->token->$claim ?? null;
    }

    /**
     * Is this token expired
     * @return bool
     */
    protected function isExpired()
    {
        $exp = \DateTime::createFromFormat( 'U', $this->getClaimOrNull( self::EXPIRY ) );
        return !$exp || $exp <= ( new DateTime );
    }

    /**
     * Does this token have a user id
     * @return bool
     */
    protected function hasUserId()
    {
        return (bool)$this->getClaimOrNull( self::USER_ID );
    }

    /**
     * Is this token for labs
     * @return bool
     */
    protected function isAllowedAppId()
    {
        return in_array( $this->getClaimOrNull( self::APP_ID ), $this->appIdProvider->getAppIds() );
    }

    /**
     * Verify the token
     * @param Request $request
     * @return bool
     */
    public function isAuthorised( Request $request )
    {
        $header = $request->headers->get( 'Authorization' );

        if (strtolower($this->key->getAlgorithm()) === 'none') {
            return false;
        }

        if ( $header ) {
            try{
                $this->token = JWT::decode( $this->extractJwtFromHeader($header), $this->key );
            } catch ( \Exception $e ){
                return false;
            }
        }

        if( $this->isExpired() || !$this->hasUserId() || !$this->isAllowedAppId() ) {
            return false;
        }

        return true;
    }

    /**
     * Get the user id from the token
     * @return mixed|null
     */
    public function getUserId()
    {
        return $this->getClaimOrNull( self::USER_ID );
    }

    /**
     * Get the group id from the token
     * @return mixed|null
     */
    public function getGroupId()
    {
        return $this->getClaimOrNull( self::GROUP_ID );
    }

    /**
     * @return bool
     */
    public function getIsAdmin()
    {
        return (bool)$this->getClaimOrNull( self::IS_ADMIN );
    }

    /**
     * @return array
     */
    public function getSegments()
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

    protected function extractJwtFromHeader( $header )
    {
        if( strpos( $header, self::BEARER ) === 0 ){
            return substr( $header, strlen( self::BEARER ) );
        }
        return $header;
    }
}
