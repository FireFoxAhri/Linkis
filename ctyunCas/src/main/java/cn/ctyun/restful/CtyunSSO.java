package cn.ctyun.restful;


import java.net.URI;

import cn.ctyun.utils.CasValidate;
import com.webank.wedatasphere.linkis.gateway.config.GatewayConfiguration;
import com.webank.wedatasphere.linkis.gateway.http.GatewayContext;
import com.webank.wedatasphere.linkis.gateway.security.GatewaySSOUtils;
import com.webank.wedatasphere.linkis.gateway.security.sso.SSOInterceptor;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;

@Path("luban")
@Component

//@RestController
//@RequestMapping("luban")
public class CtyunSSO implements SSOInterceptor {

//    @GetMapping("login")
    @Path("login")
    public void casLogin(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
        response.setHeader("Location", "http://ai.ctyun.cn:8088");
    }

    @Override
    public String getUser(GatewayContext gatewayContext) {
        try {
            GatewaySSOUtils.logger().info("url:"+gatewayContext.getRequest().getQueryParams());
            GatewaySSOUtils.logger().info("getQueryParams:"+gatewayContext.getRequest().getQueryParams().get("ticket"));
            String[] tickets = gatewayContext.getRequest().getQueryParams().get("ticket");
            String tk = tickets[0];
            GatewaySSOUtils.logger().info("ticket:"+tk);
            JSONObject result = CasValidate.validate(tk);
            String user = (String) result.get("name");
            GatewaySSOUtils.logger().info("username:"+user);

            //目前是同名用户，直接用linkis的cookie，如果后续变动，再维护sso自己的cookie
            GatewaySSOUtils.setLoginUser(gatewayContext, user);
            return user;
        }catch (Exception e){
            GatewaySSOUtils.logger().error("Exception:"+e);
        }

        return null;
    }

    @Override
    public void logout(GatewayContext gatewayContext) {
        GatewaySSOUtils.removeLoginUser(gatewayContext);
    }

    @Override
    public String redirectTo(URI requestUrl) {
        GatewaySSOUtils.logger().info("redirectTo:"+requestUrl);
        return "http://www.ctyun.cn/cas/login?service=" + GatewayConfiguration.SSO_LOGIN_URL().getValue();
    }
}
