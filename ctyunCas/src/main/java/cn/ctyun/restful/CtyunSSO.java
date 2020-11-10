package cn.ctyun.restful;


import java.io.IOException;
import java.net.URI;

import cn.ctyun.utils.CasValidate;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.webank.wedatasphere.linkis.gateway.config.GatewayConfiguration;
import com.webank.wedatasphere.linkis.gateway.http.GatewayContext;
import com.webank.wedatasphere.linkis.gateway.security.GatewaySSOUtils;
import com.webank.wedatasphere.linkis.gateway.security.sso.SSOInterceptor;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
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
            String name = (String) result.get("name");
            String email = (String) result.get("email");
            String userId = (String) result.get("userId");
            GatewaySSOUtils.logger().info("username:"+name);

            String userName;
            try {
                userName = this.registerUser(userId, name, email);
            }catch (Exception e){
                GatewaySSOUtils.logger().warn("授权异常:"+e);
                userName = name;
            }
            GatewaySSOUtils.logger().info("登陆用户:"+userName);
            GatewaySSOUtils.setLoginUser(gatewayContext, userName);
            return userName;
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

    private String registerUser(String userId, String name, String email) throws IOException {
        String url = GatewayConfiguration.LUBAN_REGISTER_URL().getValue();
        GatewaySSOUtils.logger().info("registerUser url:"+url);

        ObjectMapper body = new ObjectMapper();
        ObjectNode node = body.createObjectNode();
        node.put("userId", userId);
        node.put("email", email);
        node.put("name", name);
        String JSON_STRING = node.toString();

        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(url);
        HttpEntity stringEntity = new StringEntity(JSON_STRING, ContentType.APPLICATION_JSON);
        httpPost.setEntity(stringEntity);

        CloseableHttpResponse response = null;
        try {
            response = httpclient.execute(httpPost);
            HttpEntity entity = response.getEntity();
            String responseContent = EntityUtils.toString(entity, "UTF-8");
            if (response.getStatusLine().getStatusCode() == 200 && responseContent != null) {
                //还有业务错误 需要排除
                if(responseContent.contains("{\"success\":1")){
                    GatewaySSOUtils.logger().error("注册用户失败：" +responseContent);
                    return null;
                }
                return responseContent;
            }else {
                GatewaySSOUtils.logger().error("注册用户失败：");
                return null;
            }
        }
        finally {
            if (response != null) {
                response.close();
            }
            httpclient.close();
        }
    }
}
