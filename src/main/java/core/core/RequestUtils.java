package core.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.json.simple.JSONObject;

import java.io.File;
import java.util.Map;

public class RequestUtils {
    private String url;
    private String token;
    private Method method;
    private BodyType bodyType;
    private Object oBody;
    private Map<String, Object> mBody;
    private String sBody;
    private boolean isEncrypt = false;

    public RequestUtils() {
    }

    public RequestUtils(String url, String token, Method method) {
        this.url = url;
        this.method = method;
        this.token = token;
    }


    public RequestUtils(String url, Method method, BodyType bodyType, Object oBody, boolean isEncrypt) {
        this.url = url;
        this.method = method;
        this.bodyType = bodyType;
        this.oBody = oBody;
        this.isEncrypt = isEncrypt;
    }

    public RequestUtils(String url, Method method, BodyType bodyType, Map<String, Object> mBody, boolean isEncrypt) {
        this.url = url;
        this.method = method;
        this.bodyType = bodyType;
        this.mBody = mBody;
        this.isEncrypt = isEncrypt;
    }

    public RequestUtils(String url, Method method, BodyType bodyType, String sBody, boolean isEncrypt) {
        this.url = url;
        this.method = method;
        this.bodyType = bodyType;
        this.sBody = sBody;
        this.isEncrypt = isEncrypt;
    }

    public RequestUtils(String url, String token, Method method, BodyType bodyType, Object oBody, boolean isEncrypt) {
        this.url = url;
        this.token = token;
        this.method = method;
        this.bodyType = bodyType;
        this.oBody = oBody;
        this.isEncrypt = isEncrypt;
    }

    public RequestUtils(String url, String token, Method method, BodyType bodyType, Map<String, Object> mBody, boolean isEncrypt) {
        this.url = url;
        this.token = token;
        this.method = method;
        this.bodyType = bodyType;
        this.mBody = mBody;
        this.isEncrypt = isEncrypt;
    }

    public RequestUtils(String url, String token, Method method, BodyType bodyType, String sBody, boolean isEncrypt) {
        this.url = url;
        this.token = token;
        this.method = method;
        this.bodyType = bodyType;
        this.sBody = sBody;
        this.isEncrypt = isEncrypt;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Method getMethod() {
        return method;
    }

    public void setMethod(Method method) {
        this.method = method;
    }

    public BodyType getBodyType() {
        return bodyType;
    }

    public void setBodyType(BodyType bodyType) {
        this.bodyType = bodyType;
    }

    public Object getoBody() {
        return oBody;
    }

    public void setoBody(Object oBody) {
        this.oBody = oBody;
    }

    public Map<String, Object> getmBody() {
        return mBody;
    }

    public void setmBody(Map<String, Object> mBody) {
        this.mBody = mBody;
    }

    public String getsBody() {
        return sBody;
    }

    public void setsBody(String sBody) {
        this.sBody = sBody;
    }

    public Boolean getEncrypt() {
        return isEncrypt;
    }

    public void setEncrypt(Boolean encrypt) {
        isEncrypt = encrypt;
    }

    public RequestSpecification getRequest() {
        return RestAssured.given()
                .when();
    }

    public RequestSpecification getRequest(String token) {
        return RestAssured.given()
                .header("Authorization", "Bearer " + token)
                .when();
    }

    public void decryptResponseAndLog(Response rs) {
        Response response = Encrypt.getDecryptRS(rs);
        response.then().log().all();
    }

    private void setMultiPathWithMap(RequestSpecification requestSpecification, Map<String, Object> mBody) {
        for (Map.Entry<String, Object> entry : mBody.entrySet()) {
            requestSpecification.multiPart(entry.getKey(), entry.getValue());
        }
    }

    private void setMultiPathWithObject(RequestSpecification requestSpecification, Object oBody) {
        Map<String, Object> map = convertClsToMap(oBody);
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (isFile(entry.getValue())) entry.setValue(new File(entry.getValue().toString()));
        }

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if(entry.getValue() != null ) System.out.println(entry.getValue().getClass().getSimpleName());
        }
        setMultiPathWithMap(requestSpecification, map);
    }

    private boolean isFile(Object path){
        if(path != null){
            File file = new File(path.toString());
            if (file.exists()){
                return true;
            }
        }
        return false;
    }
    private String convertClsToJson(Object cls) {
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        try {
            return ow.writeValueAsString(cls);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private Map<String, Object> convertClsToMap(Object cls) {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> map = objectMapper.convertValue(cls, Map.class);
        return map;
    }

    public Response send() {
        RequestSpecification requestSpecification = (token == null) ? getRequest() : getRequest(getToken());
        String json = "";
        if (getBodyType() != null) {
            switch (getBodyType()) {
                case BODY:
                    requestSpecification.contentType(ContentType.JSON);
                    if (getsBody() != null) {
                        requestSpecification.body(getsBody());
                    }

                    if (getoBody() != null) {
                        if (isEncrypt) {
                            json = convertClsToJson(getoBody());
                            requestSpecification.body(Encrypt.encryptRequest(json));
                        } else {
                            requestSpecification.body(getoBody());
                        }
                    }

                    if (getmBody() != null) {
                        if (isEncrypt) {
                            json = new JSONObject(getmBody()).toString();
                            requestSpecification.body(Encrypt.encryptRequest(json));
                        } else {
                            requestSpecification.body(getmBody());
                        }
                    }
                    break;

                case FORM:
                    break;
                case MULTI_PART:
                    requestSpecification.contentType(ContentType.MULTIPART);
                    if (getoBody() != null) {
                        setMultiPathWithObject(requestSpecification, getoBody());
                    }

                    if (getmBody() != null) {
                        setMultiPathWithMap(requestSpecification, getmBody());
                    }
                    break;
                case PATH_PARAMS:
                    if (getsBody() != null) {
                        requestSpecification.pathParams(getmBody());
                    }
                    break;
                case QUERY_PARAMS:
                    if (getmBody() != null)
                        requestSpecification.queryParams(getmBody());

                    if (getoBody() != null)
                        if (isEncrypt) {
                            json = convertClsToJson(getoBody());
                            requestSpecification.queryParams(convertClsToMap(Encrypt.encryptRequest(json)));
                        } else {
                            requestSpecification.queryParams(convertClsToMap(getoBody()));
                        }
                    break;
                default:
                    System.out.println("Khong co body..");
                    break;
            }
        }

        requestSpecification.log().all();


        Response response = null;
        switch (getMethod()) {
            case GET:
                response = requestSpecification.get(getUrl());
                break;
            case PUT:
                response = requestSpecification.put(getUrl());
                break;
            case POST:
                response = requestSpecification.post(getUrl());
                break;
            case DELETE:
                response = requestSpecification.delete(getUrl());
                break;
        }

        if (response.getHeader("Encryption") != null && response.getHeader("Encryption").equalsIgnoreCase("true")) {
            System.out.println("Body before encrypt: \n" + json);
            response = Encrypt.getDecryptRS(response);
        }
        response.then().log().all();
        return response;
    }
}
