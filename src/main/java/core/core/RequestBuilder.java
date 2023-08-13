package core.core;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.response.Response;
import java.util.Map;

public class RequestBuilder {
    private String url;
    private String token;
    private Method method;
    private BodyType bodyType;
    private Object oBody;
    private Map<String, Object> mBody;
    private String sBody;
    private boolean isEncrypt;

    public static RequestBuilder given() {
        return new RequestBuilder();
    }
    protected <T> T mapping (Object fromCls, Class<T> toClass){
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,false);
        return objectMapper.convertValue(fromCls,toClass);
    }

    public RequestBuilder body(String sBody) {
        this.bodyType = BodyType.BODY;
        this.sBody = sBody;
        return this;
    }

    public RequestBuilder body(Object oBody, Class<?> cls) {
        this.bodyType = BodyType.BODY;
        this.oBody = mapping(oBody, cls);
        return this;
    }

    public RequestBuilder body(Object oBody) {
        this.bodyType = BodyType.BODY;
        this.oBody = oBody;
        return this;
    }


    public RequestBuilder body(Map<String, Object> mBody) {
        this.bodyType = BodyType.BODY;
        this.mBody = mBody;
        return this;
    }

    public RequestBuilder post(String url) {
        this.method = Method.POST;
        this.url = url;
        return this;
    }

    public RequestBuilder get(String url) {
        this.method = Method.GET;
        this.url = url;
        return this;
    }

    public RequestBuilder delete(String url) {
        this.method = Method.DELETE;
        this.url = url;
        return this;
    }

    public RequestBuilder put(String url) {
        this.method = Method.PUT;
        this.url = url;
        return this;
    }

    public RequestBuilder auth(String token) {
        this.token = token;
        return this;
    }

    public RequestBuilder queryParams(Object oBody) {
        this.bodyType = BodyType.QUERY_PARAMS;
        this.oBody = oBody;
        return this;
    }

    public RequestBuilder queryParams(Map<String, Object> mBody) {
        this.bodyType = BodyType.QUERY_PARAMS;
        this.mBody = mBody;
        return this;
    }

    public RequestBuilder multiPart(Object oBody) {
        this.bodyType = BodyType.MULTI_PART;
        this.oBody = oBody;
        return this;
    }

    public RequestBuilder multiPart(Map<String, Object> mBody) {
        this.bodyType = BodyType.MULTI_PART;
        this.mBody = mBody;
        return this;
    }

    public RequestBuilder encrypt() {
        this.isEncrypt = true;
        return this;
    }

    private RequestUtils build() {
        System.out.println("@@@ " + this.isEncrypt);
        if (this.sBody != null)
           return new RequestUtils(this.url, this.token, this.method, this.bodyType, this.sBody, this.isEncrypt);
        if (this.oBody != null)
            return new RequestUtils(this.url, this.token, this.method, this.bodyType, this.oBody, this.isEncrypt);
        if (this.mBody != null)
            return new RequestUtils(this.url, this.token, this.method, this.bodyType, this.mBody, this.isEncrypt);
        return new RequestUtils(this.url, this.token, this.method);
    }

    public Response send() {
        return build().send();
    }
}
