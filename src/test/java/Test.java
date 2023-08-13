import core.core.RequestBuilder;
import java.util.HashMap;
import java.util.Map;


public class Test {

    public static void main(String[] args) {
//        Response response;
//        SignInRQ body = new SignInRQ();
//        body.setGdrLogin("0987654326");
//        body.setPassword("123456");
//        body.setCountry("VN");
//        body.setDeviceId("3m4ihc9y8TqoZ2cAbF3yUEmGeLCbGdkV6ohmasp5/us=");
//        response= RequestBuilder.given()
//                .post("https://apis1.globedr.com/api/v1/Account/ESignIn")
//                .body(body, SignInRQ.class)
//                .encrypt()
//                .send();
//
//        String token = response.jsonPath().get("data.accessToken");
//        System.out.println(token);
//        UpdateInfoRQ bodyUpdate = new UpdateInfoRQ();
//        bodyUpdate.setDisplayName("Tuan");
//        bodyUpdate.setAddress("73 Rạch Bùng Binh");
//        bodyUpdate.setDob("2000-11-09T00:00:00.000");
//        bodyUpdate.setPhone("09090909090");
//        bodyUpdate.setGender("2");
//        bodyUpdate.setCountry("VN");
//
//        RequestBuilder.given()
//                .put("https://apis1.globedr.com/api/v1/Account/EUpdatePersonalInfo")
//                .auth(token)
//                .body(bodyUpdate, UpdateInfoRQ.class)
//                .encrypt()
//                .send();
//
//        RequestBuilder.given()
//                .get("https://apis1.globedr.com/api/v1/Account/GetPersonalInfo")
//                .auth(token)
//                .send();
    public static login (Map<String,Object> dsdd){};

        Map<String,Object> loginBody = new HashMap<>();
        loginBody.put("gdrLogin","0392777320");
        loginBody.put("password","123456");
        loginBody.put("country","VN");
        loginBody.put("deviceId","3m4ihc9y8TqoZ2cAbF3yUEmGeLCbGdkV6ohmasp5/us=");

//        Map<String, Object> encryptBody = new HashMap<>();
//        encryptBody.put("k",encryptDESKeyWithRSA());
//        encryptBody.put("d",encryptDataWithDesKey(loginBody));

        RequestBuilder.given()
                .post("https://apis1.globedr.com/api/v1/Account/ESignIn")
                .body(loginBody)
                .encrypt()
                .send();

    }





//        Map<String,Object> map = new HashMap<>();
//        map.put("chunkNumber", 1);
//        map.put("resumableTotalChunks",1);
//        map.put("fileName", "hinh");
//        map.put("file",new File("D:\\BT\\JavaBT\\restAssureEx\\File\\hinh.png"));
//        map.put("resumableType", "png");
//        map.put("resumableIdentifier", "hinh.png");
//
//        AddFilesRQ addFilesRQ = new AddFilesRQ();
//        addFilesRQ.setFile(new File("D:\\BT\\JavaBT\\restAssureEx\\File\\hinh.png"));
//        addFilesRQ.setFileName("hinh");
//        addFilesRQ.setResumableType("png");
//        addFilesRQ.setResumableIdentifier("hinh.png");
//
//        RequestBuilder.given()
//                .post("https://apis1.globedr.com/api/v1/Consult/AddFiles")
//                .auth("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoidzk2N3FWV1U3VVplVE15akg2VWFMajd2V1huenNuVEdSeUt1bndlNHpNZzhBaU5xS1hLcjZhVHJCMzByck1tSDEzbFpmVlhGaEVrQmV6eUVJOXF0ZDZGLy9ZcWsrdTBVU2xLMTRKNWlpcVdVMW52S1owcmVPc0wxc3BBbmhpR3JPalNNb3JvMS9PQTQxUzZPbEdZdFRrcE9hbm9La2dQLzh3emVPSVlnZWJheWYyR3g0N3RCTWlUU3UrN0dFUG5KSkFtYzlDRzdNaXp3a0IwdEVOSWRseEtyMHEvQlQvL0lHTDZ2Z2RrdjJpSjVFb3FZTEducVZ2NHJwamhZcTdQamRPQXZOV0RxMm1ialpvdmZjUVBkSCtTQkIxQWxrU2tZIiwianRpIjoiNDNiODBmM2EtNjI5Yi00OWJhLWIwNWQtOTU4MGFiMjMyZmE3IiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiMiIsImNyZWF0ZWREYXRlIjoiMDMvMTUvMjAyMiAwNjoxMTo0OCIsImlzcyI6Imdsb2JlZHIiLCJhdWQiOiJnbG9iZWRyIn0.14_GKGuwSDlIMJ4OJBwIJ-nz5MgrKYoYQxr4mwuKBOw")
//                .body(addFilesRQ)
//                .send();



}
