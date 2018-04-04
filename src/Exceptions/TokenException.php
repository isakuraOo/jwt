<?php
/**
 * @author iSakura <i@joosie.cn>
 */
namespace Joosie\JWT\Exceptions;

use Exception;

/**
* TOKEN 异常处理类
*/
class TokenException extends Exception
{
    const CODE = 500;
    
    function __construct($message, $code = self::CODE)
    {
        parent::__construct($message, $code);
    }
}