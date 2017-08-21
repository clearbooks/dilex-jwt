<?php
namespace Clearbooks\Dilex\JwtGuard;

use DateTime;
use Emarref\Jwt\Algorithm\AlgorithmInterface;
use Emarref\Jwt\Algorithm\None;
use Emarref\Jwt\Encryption\Factory as EncryptionFactory;
use Emarref\Jwt\Exception\VerificationException;
use Emarref\Jwt\Jwt;
use Emarref\Jwt\Token;
use Emarref\Jwt\Verification\Context;
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
     * @var AlgorithmInterface
     */
    protected $algorithm;

    /**
     * @var Token
     */
    protected $token;

    /**
     * @var AppIdProvider
     */
    protected $appIdProvider;

    /**
     * @param Jwt $jwt
     * @param AlgorithmInterface $algorithm
     * @param AppIdProvider $appIdProvider
     */
    public function __construct( Jwt $jwt, AlgorithmInterface $algorithm, AppIdProvider $appIdProvider )
    {
        $this->jwt = $jwt;
        $this->algorithm = $algorithm;
        $this->token = new Token;
        $this->appIdProvider = $appIdProvider;
    }

    /**
     * Get a claim if we have one or return null
     * @param string $claim the name of the claim
     * @return mixed
     */
    protected function getClaimOrNull( $claim )
    {
        $claim = $this->token->getPayload()->findClaimByName( $claim );
        return $claim ? $claim->getValue() : null;
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
        $context = new Context( EncryptionFactory::create( $this->algorithm ) );

        if ( $header ) {
            try{
                $this->token = $this->jwt->deserialize( $this->extractJwtFromHeader($header) );
            } catch ( \Exception $e ){
                return false;
            }
        }

        if ( $this->algorithm instanceof None ) {
            return false;
        }

        if( $this->isExpired() || !$this->hasUserId() || !$this->isAllowedAppId() ) {
            return false;
        }

        try {
            return $this->jwt->verify( $this->token, $context );
        } catch ( VerificationException $e ) {
            return false;
        }
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
        return is_array( $segments ) ? $segments : [ ];
    }

    protected function extractJwtFromHeader( $header )
    {
        if( strpos( $header, self::BEARER ) === 0 ){
            return substr( $header, strlen( self::BEARER ) );
        }
        return $header;
    }
}
