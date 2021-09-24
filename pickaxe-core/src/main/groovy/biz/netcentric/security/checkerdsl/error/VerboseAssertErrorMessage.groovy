package biz.netcentric.security.checkerdsl.error

public class VerboseAssertErrorMessage {

    /**
     * Extension method for String type.
     * Use as follow: assert "The condition must be true" | x==y
     * @param self message itself
     * @param condition condition to check
     * @return initial condition value
     */
    public static Boolean or(String self, Boolean condition) {
        return condition
    }

    public static Boolean or(String self, Object object) {
        if(object instanceof Boolean){
            return object
        }
        return object != null
    }
}
