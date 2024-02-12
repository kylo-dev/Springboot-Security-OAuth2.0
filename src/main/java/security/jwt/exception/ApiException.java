package security.jwt.exception;

public class ApiException extends RuntimeException{

    private final ErrorType errorType;

    public ApiException(ErrorType errorType) {
        super(errorType.getMessage());
        this.errorType = errorType;
    }

    public ErrorType getErrorType() {
        return errorType;
    }
}
