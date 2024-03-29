package burp;

public class Path {
   public final static String[] payloads={
           "/actuator",
           "/manage",
           "/manage/env",
           "/env",
           "/actuator/env",
           "/swagger-resources",
           "/api/v2/api-docs",
           "/v2/api-docs",
           "/api-docs",
           "/swagger-ui.html",
           "/swagger-ui/index.html"
   };

   public final static String[] fullPath={
           "/actuator",
           "/manage",
           "/manage/env",
           "/env",
           "/actuator/env",
           "/swagger-resources",
           "/api/v2/api-docs",
           "/v2/api-docs",
           "/api-docs",
           "/swagger-ui.html",
           "/swagger-ui/index.html",
   };

   public final static String[] values={
           "swagger-ui.css",
           "******",
           "swaggerversion",
           "actuator/info",
           "actuator/health",
           "profiles",
           "swagger"
   };


}
