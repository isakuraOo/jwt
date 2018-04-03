<?php
/**
 * @author Jackson <i@joosie.cn>
 * @since v1.0.0
 */
namespace Joosie\JWT;

/**
* 授权令牌 Token 处理类
*/
class Token
{
    const SECRET_KEY = 'xWUCg1avJSvF3TLTEEk32I530lxsCaiS'; // 加密令牌签名的密钥

    const EXPIRE_TIME = 900; // 授权令牌的有效期时长
    const REFRESH_TIME = 7200; // 刷新令牌的有效期时长

    const DEFAULT_ALGO = 'sha256'; // 默认使用的 hash 方法

    /**
     * Token 令牌头部信息
     * 默认为 type algo 两个数据
     * type 指定 Token 遵循 JWT 规范，algo 声明最后 secret 的加密
     * @var array
     */
    private $header = [
        'type'  => 'JWT', // 必须
        'algo'  => 'sha256', // 如不设置，默认 sha256
    ];

    /**
     * Token 令牌主体信息
     * 用户可以自定义里面的内容
     * @var array
     */
    private $payload = [];

    /**
     * 授权令牌
     * @var null
     */
    private $authorization = null;

    /**
     * 授权令牌属性数组
     * @var array
     */
    private $authorizationOptions = [
        'header'    => null,
        'payload'   => null,
        'secret'    => null,
    ];

    public function __construct(array $config = [])
    {
        
    }

    /**
     * 设置令牌头部信息
     * @param array $header 头部信息数组
     */
    public function setHeader( array $header )
    {
        $this->header = $header;
        return $this;
    }

    /**
     * 获取令牌头部信息
     * @return array 头部信息数组
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * 设置令牌主体信息
     * @param array $payload 主体信息数组
     */
    public function setPayload( array $payload )
    {
        ksort( $payload );
        $this->payload = $payload;
        return $this;
    }

    /**
     * 获取令牌主体信息
     * @return array 主体信息数组
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * 设置授权令牌
     * @param string $authorization 授权令牌
     */
    public function setAuthorization( $authorization )
    {
        $this->authorization = $authorization;
        return $this;
    }

    /**
     * 获取请求头部授权令牌数据
     * @return string 授权令牌
     */
    public function getAuthorization()
    {
        return $this->authorization;
    }

    /**
     * 设置令牌属性
     * @param string $key   属性名 header|payload|secret
     * @param string $value 属性值
     */
    public function setAuthorizationOption( $key, $value )
    {
        if ( isset( $this->authorizationOptions[$key] ) )
            $this->authorizationOptions[$key] = $value;
        return $this;
    }

    /**
     * 获取某个令牌属性
     * @param  string $key 属性名 header|payload|secret
     * @return string      属性值
     */
    public function getAuthorizationOption( $key )
    {
        return isset( $this->authorizationOptions[$key] ) ? $this->authorizationOptions[$key] : null;
    }

    /**
     * 设置令牌属性
     * @param array $options 属性数组
     */
    public function setAuthorizationOptions( array $options )
    {
        $this->authorizationOptions = $options;
        return $this;
    }

    /**
     * 获取令牌属性数组
     * @return array 令牌属性数组
     */
    public function getAuthorizationOptions()
    {
        return $this->authorizationOptions;
    }

    /**
     * 从请求头部获取授权令牌数据
     * @return string 授权令牌
     */
    public function getAuthorizationFromHeader()
    {
        if ( isset( $_SERVER['PHP_AUTH_DIGEST'] ) )
            $authorization = $_SERVER['PHP_AUTH_DIGEST'];
        elseif ( isset( $_SERVER['PHP_AUTH_USER'] ) && isset( $_SERVER['PHP_AUTH_PW'] ) )
            $authorization = base64_encode( $_SERVER['PHP_AUTH_USER'] . ':' . $_SERVER['PHP_AUTH_PW'] );
        elseif ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) )
            $authorization = $_SERVER['HTTP_AUTHORIZATION'];
        else
            $authorization = null;
        return !empty( $authorization ) ? str_replace( 'Bearer ', '', $authorization ) : $authorization;
    }

    /**
     * 设置授权令牌到响应头
     */
    public function setAuthorizationToHeader()
    {
        $authorization = $this->getAuthorization();
        header( 'Authorization: Bearer ' . $authorization );
        return $this;
    }

    /**
     * 签发一个新的授权令牌
     * @param  array  $header  头部信息数组
     * @param  array  $payload 主体信息数组
     */
    public function generateToken( $header = [], $payload = [] )
    {
        if ( !empty( $header ) )
            $this->setHeader( $header );
        if ( !empty( $payload ) )
            $this->setPayload( $payload );

        $time = time();
        $this->payload['tokenExpiredAt'] = $time + self::EXPIRE_TIME;
        $this->payload['refreshExpiredAt'] = $time + self::REFRESH_TIME;
        $this->payload['refreshToken'] = $this->getRefreshToken();
        return $this->sign();
    }

    /**
     * 令牌签名
     */
    private function sign()
    {
        $header = $this->getHeader();
        $payload = $this->getPayload();
        $algo = isset( $header['algo'] ) ? $header['algo'] : self::DEFAULT_ALGO;
        $options['header'] = base64_encode( json_encode( $header, true ) );
        $options['payload'] = base64_encode( json_encode( $payload, true ) );
        $data = $options['header'] . $options['payload'] . self::SECRET_KEY;
        $options['secret'] = hash( $algo, $data );
        return $this->setAuthorizationOptions( $options )
            ->setAuthorization( implode( '.', $options ) );
    }

    /**
     * 获取访问用户的真实 IP 地址
     * @return string|null IP 地址
     */
    private function getClientIp()
    {
        // 偷懒直接用了框架自带方法。。。
        return app( 'request' )->getClientIp();
    }

    /**
     * 获取刷新令牌
     * 刷新令牌的实际作用有待研究
     * @return string 刷新令牌
     */
    private function getRefreshToken()
    {
        $payload = $this->getPayload();
        $refreshExpiredAt = $payload['refreshExpiredAt'];
        $ip = $this->getClientIp();
        return md5( ip2long( $ip ) . $refreshExpiredAt );
    }

    /**
     * 授权令牌校验
     * @return boolean 检验是否通过
     */
    public function valid()
    {
        $authorization = $this->getAuthorizationFromHeader();
        $tmpTokenArr = explode( '.', $authorization );
        if ( !is_array( $tmpTokenArr ) || count( $tmpTokenArr ) != 3 )
            return false;

        list( $options['header'], $options['payload'], $options['secret'] ) = $tmpTokenArr;
        $header = json_decode( base64_decode( $options['header'] ), true );
        $payload = json_decode( base64_decode( $options['payload'] ), true );
        $this->setAuthorization( $authorization )
            ->setAuthorizationOptions( $options )
            ->setHeader( $header )
            ->setPayload( $payload );
        return $this->checkSign() && $this->checkExpire();
    }

    /**
     * 签名校验
     * @return boolean      签名是否通过
     */
    private function checkSign()
    {
        $header = $this->getHeader();
        $algo = isset( $header['algo'] ) ? $header['algo'] : self::DEFAULT_ALGO;
        if ( !in_array( $algo, hash_algos() ) )
            return false;

        $data = $this->getAuthorizationOption( 'header' )
            . $this->getAuthorizationOption( 'payload' )
            . self::SECRET_KEY;
        $sign = hash( $algo, $data );
        return $sign === $this->getAuthorizationOption( 'secret' );
    }

    /**
     * 过期校验
     * @return boolean 是否已过期
     */
    private function checkExpire()
    {
        $payload = $this->getPayload();
        return time() < $payload['refreshExpiredAt'];
    }

    /**
     * 刷新令牌
     * 建议在授权令牌校验通过后调用一次
     * 该方法只会在需要刷新的时段执行刷新操作
     */
    public function refreshToken()
    {
        $payload = $this->getPayload();
        $nowTime = time();
        if (
            $payload['tokenExpiredAt'] < $nowTime
            && $nowTime < $payload['refreshExpiredAt']
            && $this->checkRefreshToken()
        ) {
            $this->generateToken()->setAuthorizationToHeader();
        }
    }

    /**
     * 校验刷新令牌
     * @return boolean 
     */
    private function checkRefreshToken()
    {
        $payload = $this->getPayload();
        $refreshToken = $payload['refreshToken'];
        $refreshExpiredAt = $payload['refreshExpiredAt'];
        $ip = $this->getClientIp();
        return md5( ip2long( $ip ) . $refreshExpiredAt ) === $refreshToken;
    }

}