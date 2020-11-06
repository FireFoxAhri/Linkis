package cn.ctyun.utils;

import com.webank.wedatasphere.linkis.gateway.config.GatewayConfiguration;
import com.webank.wedatasphere.linkis.gateway.security.GatewaySSOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.json.XML;

import java.io.IOException;
import java.util.Date;

public class CasValidate {

    static String appId = GatewayConfiguration.APP_ID().getValue();
    static String appSecret = GatewayConfiguration.APP_SECRET().getValue();
    static String service = GatewayConfiguration.SSO_LOGIN_URL().getValue();// http://ai.ctyun.cn:8088/api/rest_j/v1/application/ssologin

    public static JSONObject validate(String ticket) throws IOException {
        HmacSHA256 coder = new HmacSHA256();
        String now = new Date().getTime()+"";
        StringBuffer toSign = new StringBuffer();
        toSign.append(appId).append("@");
        toSign.append(service).append("@");
        toSign.append(ticket).append("@");
        toSign.append(now);
        String signed = coder.encode(toSign.toString(),appSecret);
        GatewaySSOUtils.logger().info("签名文本:"+toSign+"<--->生成的签名是:" + signed);

        StringBuffer url = new StringBuffer();
        url.append(GatewayConfiguration.LUBAN_CAS_URL().getValue()+service+"&ticket="+ticket).append("&")
                .append("appId=").append(appId).append("&")
                .append("timestamp=").append(now).append("&")
                .append("signature=").append(signed);

        GatewaySSOUtils.logger().info("url:"+url);
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpGet httpget = new HttpGet(url.toString());
        CloseableHttpResponse response = null;
        JSONObject jsonObj = null;
        try {
            response = httpclient.execute(httpget);
            if (response.getStatusLine().getStatusCode() == 200) {
                String content = EntityUtils.toString(response.getEntity(), "UTF-8");
                jsonObj = XML.toJSONObject(content);
                if(jsonObj.getJSONObject("cas:serviceResponse").has("cas:authenticationSuccess")){
                  JSONObject userInfo = jsonObj.getJSONObject("cas:serviceResponse").getJSONObject("cas:authenticationSuccess").getJSONObject("cas:attributes");
                    GatewaySSOUtils.logger().info("验证成功：userInfo:"+userInfo);
                  if(userInfo != null){
                      return userInfo;
                  }
                }else {
                    GatewaySSOUtils.logger().error("验证失败："+ jsonObj.getJSONObject("cas:serviceResponse"));
                }
            }
        }
        finally {
            if (response != null) {
                response.close();
            }
            httpclient.close();
        }

        return jsonObj;
    }
}
