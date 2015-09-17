<?php


namespace Clearbooks\Dilex\JwtGuard;


use Symfony\Component\HttpFoundation\Request;

class RequestAuthoriserStub implements RequestAuthoriser
{
    private $valid;

    public function __construct( $isValid )
    {
        $this->valid = $isValid;
    }

    public function isAuthorised( Request $request )
    {
        return $this->valid;
    }
}