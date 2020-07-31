package cn.ctyun.utils;

import com.anysoft.util.BaseException;
import com.anysoft.util.code.coder.MD5;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * HmacSHA256编码
 * 
 * @author yyduan
 * @since 1.6.10.6
 * 
 */
public class HmacSHA256 implements Coder {
	protected static final Logger LOG = LoggerFactory.getLogger(MD5.class);
	
	protected ThreadLocal<Mac> macLocal = new ThreadLocal<Mac>(){
        protected Mac initialValue() {
        	try {
        		return Mac.getInstance(getAlgorithm());
        	}catch (Exception ex){
    			LOG.error(ExceptionUtils.getStackTrace(ex));
    			return null;
        	}
        };
    };
	
	public String getAlgorithm() {
		return "HmacSHA256";
	}
	
	@Override
	public String encode(String data, String key) {
		try {
        	byte [] byteKey = Base64.decodeBase64(key);
        	SecretKey secretKey = new SecretKeySpec(byteKey, getAlgorithm());
            Mac mac = macLocal.get();
            mac.init(secretKey);  
            byte[] bytes = mac.doFinal(data.getBytes());  
            return Base64.encodeBase64URLSafeString(bytes);
		}catch (Exception ex){
			LOG.error(ExceptionUtils.getStackTrace(ex));
			return data;
		}
	}

	@Override
	public String decode(String data, String key) {
		return data;
	}

	@Override
	public String createKey() {
		try {
			KeyGenerator generator = KeyGenerator.getInstance(getAlgorithm());
	        SecretKey key = generator.generateKey();
	        return Base64.encodeBase64URLSafeString(key.getEncoded());
		} catch (NoSuchAlgorithmException e) {
			throw new BaseException("core.e1000",ExceptionUtils.getStackTrace(e));
//			return  "core.e1000" + ExceptionUtils.getStackTrace(e);
		}
	}

	@Override
	public String createKey(String key){
		return createKey();
	}
}