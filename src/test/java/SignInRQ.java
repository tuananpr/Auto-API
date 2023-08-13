public class SignInRQ {
    private String gdrLogin;
    private String password;
    private String country;
    private String deviceId;
    private Integer language;

    public SignInRQ() {
    }

    public String getGdrLogin() {
        return gdrLogin;
    }

    public void setGdrLogin(String gdrLogin) {
        this.gdrLogin = gdrLogin;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public Integer getLanguage() {
        return language;
    }

    public void setLanguage(Integer language) {
        this.language = language;
    }
}
