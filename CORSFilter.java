// package com.alterra.demorbac.config;

// import java.io.IOException;
// import java.util.ArrayList;
// import java.util.Arrays;
// import java.util.List;
// import java.util.Optional;

// import javax.servlet.Filter;
// import javax.servlet.FilterChain;
// import javax.servlet.FilterConfig;
// import javax.servlet.ServletException;
// import javax.servlet.ServletRequest;
// import javax.servlet.ServletResponse;
// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.core.Ordered;
// import org.springframework.core.annotation.Order;
// import org.springframework.stereotype.Component;

// @Component
// @Order(Ordered.HIGHEST_PRECEDENCE)
// public class CORSFilter implements Filter {

//     @Value("${app.origin:*}")
//     private String origin;

//     @Value("${app.production:false}")
//     private boolean production;

//     @Override
//     public void init(FilterConfig filterConfig) {
//     }

//     @Override
//     public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
//             ServletException {
//         HttpServletResponse resp = (HttpServletResponse) response;
//         HttpServletRequest req = (HttpServletRequest) request;

//         if (production) {
//             List<String> origins = new ArrayList<>(Arrays.asList(origin.split(",")));
//             Optional<String> result = origins
//                     .stream()
//                     .filter(v -> v.equals(req.getHeader("Origin")))
//                     .findFirst();
//             result.ifPresent(s -> resp.setHeader("Access-Control-Allow-Origin", s));
//         } else {
//             resp.setHeader("Access-Control-Allow-Origin", req.getHeader("Origin"));
//         }

//         String methods = "GET, POST, PATCH, PUT, DELETE, OPTIONS";
//         String headers = "x-requested-with, Authorization, Content-Type, credential, X-Import-Process, X-XSRF-TOKEN";
//         String maxAge = "3600";
//         resp.setHeader("Access-Control-Allow-Methods", methods);
//         resp.setHeader("Access-Control-Allow-Headers", headers);
//         resp.setHeader("Access-Control-Max-Age", maxAge);
//         resp.setHeader("Access-Control-Allow-Credentials", "true");

//         if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
//             resp.setStatus(HttpServletResponse.SC_OK);
//         } else {
//             chain.doFilter(request, response);
//         }
//     }

//     @Override
//     public void destroy() {
//     }

// }
