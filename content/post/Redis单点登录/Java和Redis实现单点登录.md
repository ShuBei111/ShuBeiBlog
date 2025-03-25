# Java和Redis实现单点登录

使用Java和Redis实现单点登录（SSO）的核心思路是通过全局Token实现跨系统身份验证。以下是分步实现方案：

### 一、实现原理

1. **统一认证中心**：Redis作为Token存储中心
2. **Token验证流程**：
   - 用户首次登录生成全局Token
   - 子系统通过验证Redis中的Token判断登录状态
3. **跨域传递Token**：通过Cookie或URL参数传递（需处理跨域问题）

### 二、核心代码实现（Spring Boot）

#### 1. 添加依赖（pom.xml）

xml

复制

```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```



运行 HTML

#### 2. Redis配置（application.yml）

yaml

复制

```
spring:
  redis:
    host: localhost
    port: 6379
    timeout: 5000
    database: 0
```

#### 3. Token管理工具类

java

复制

```
@Component
public class TokenManager {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    private static final String TOKEN_PREFIX = "SSO_TOKEN:";
    private static final Duration TOKEN_EXPIRE = Duration.ofHours(2);

    public String createToken(String userId) {
        String token = UUID.randomUUID().toString().replace("-", "");
        redisTemplate.opsForValue().set(
            TOKEN_PREFIX + token, 
            userId, 
            TOKEN_EXPIRE
        );
        return token;
    }

    public String validateToken(String token) {
        return redisTemplate.opsForValue().get(TOKEN_PREFIX + token);
    }

    public void deleteToken(String token) {
        redisTemplate.delete(TOKEN_PREFIX + token);
    }
}
```

#### 4. 登录控制器

java

复制

```
@RestController
@RequestMapping("/auth")
public class AuthController {
    
    @Autowired
    private TokenManager tokenManager;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, 
                                  @RequestParam String password,
                                  HttpServletResponse response) {
        // 1. 验证用户名密码（模拟）
        if(!"admin".equals(username) || !"123456".equals(password)){
            return ResponseEntity.status(401).body("认证失败");
        }

        // 2. 生成Token
        String token = tokenManager.createToken(username);
        
        // 3. 写入Cookie（需处理跨域）
        Cookie cookie = new Cookie("SSO_TOKEN", token);
        cookie.setPath("/");
        cookie.setDomain(".example.com"); // 主域名
        cookie.setMaxAge(7200); // 2小时
        response.addCookie(cookie);
        
        return ResponseEntity.ok().build();
    }
}
```

#### 5. 认证拦截器

java

复制

```
public class AuthInterceptor implements HandlerInterceptor {
    
    @Autowired
    private TokenManager tokenManager;

    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) throws Exception {
        // 1. 获取Token
        Cookie[] cookies = request.getCookies();
        String token = Arrays.stream(cookies)
                .filter(c -> "SSO_TOKEN".equals(c.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);

        // 2. 验证Token
        if(token != null && tokenManager.validateToken(token) != null) {
            return true;
        }

        // 3. 跳转到登录页
        response.sendRedirect("http://sso.example.com/auth/login");
        return false;
    }
}
```

#### 6. 注册拦截器

java

复制

```
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor())
                .addPathPatterns("/**")
                .excludePathPatterns("/auth/**");
    }

    @Bean
    public AuthInterceptor authInterceptor() {
        return new AuthInterceptor();
    }
}
```

### 三、关键优化点

1. **Token加密**：建议使用JWT代替UUID，携带用户信息并签名验证

2. **跨域处理**：

   java

   复制

   ```
   // 设置CORS
   response.setHeader("Access-Control-Allow-Credentials", "true");
   response.setHeader("Access-Control-Allow-Origin", "trusted-domain.com");
   ```

3. **双Token机制**：使用AccessToken+RefreshToken提升安全性

4. **日志审计**：记录登录日志和Token操作日志

5. **限流防护**：对登录接口进行限流防止暴力破解

### 四、系统架构图

复制

```
+----------+       +------------+       +------------+
|  Client  |       |  System A  |       |  System B  |
+----+-----+       +-----+------+       +-----+------+
     |                   |                    |
     | 携带Token访问      | 携带Token访问       |
     +------------------>+                   |
     |                   |                   |
     |                   | 向Redis验证       |
     |                   +------------------>+
     |                   |                   |
     |                   |<------------------+
     |                   | 验证结果返回        |
+----+-----+       +-----v------+       +-----v------+
| Redis DB <-------+  SSO Auth  <-------+  SSO Auth  |
+----------+       +------------+       +------------+
```

### 五、注意事项

1. 使用HTTPS保证传输安全
2. 定期扫描Redis中过期Token
3. 实现Token自动续期机制
4. 禁止在URL中明文传输Token
5. 用户登出时服务端主动清除Token

以上方案实现了基于Redis的分布式会话管理，通过统一Token验证机制实现跨系统的单点登录能力。可根据实际业务需求扩展用户信息存储、多因素认证等安全措施。