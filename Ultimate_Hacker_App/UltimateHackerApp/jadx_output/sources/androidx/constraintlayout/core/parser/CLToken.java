package androidx.constraintlayout.core.parser;

/* loaded from: classes.dex */
public class CLToken extends CLElement {
    int mIndex;
    char[] mTokenFalse;
    char[] mTokenNull;
    char[] mTokenTrue;
    Type mType;

    enum Type {
        UNKNOWN,
        TRUE,
        FALSE,
        NULL
    }

    public boolean getBoolean() throws CLParsingException {
        if (this.mType == Type.TRUE) {
            return true;
        }
        if (this.mType == Type.FALSE) {
            return false;
        }
        throw new CLParsingException("this token is not a boolean: <" + content() + ">", this);
    }

    public boolean isNull() throws CLParsingException {
        if (this.mType == Type.NULL) {
            return true;
        }
        throw new CLParsingException("this token is not a null: <" + content() + ">", this);
    }

    public CLToken(char[] content) {
        super(content);
        this.mIndex = 0;
        this.mType = Type.UNKNOWN;
        this.mTokenTrue = "true".toCharArray();
        this.mTokenFalse = "false".toCharArray();
        this.mTokenNull = "null".toCharArray();
    }

    public static CLElement allocate(char[] content) {
        return new CLToken(content);
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    protected String toJSON() {
        if (CLParser.sDebug) {
            return "<" + content() + ">";
        }
        return content();
    }

    @Override // androidx.constraintlayout.core.parser.CLElement
    protected String toFormattedJSON(int indent, int forceIndent) {
        StringBuilder json = new StringBuilder();
        addIndent(json, indent);
        json.append(content());
        return json.toString();
    }

    public Type getType() {
        return this.mType;
    }

    public boolean validate(char c, long position) {
        boolean isValid = false;
        switch (this.mType) {
            case UNKNOWN:
                if (this.mTokenTrue[this.mIndex] == c) {
                    this.mType = Type.TRUE;
                    isValid = true;
                    break;
                } else if (this.mTokenFalse[this.mIndex] == c) {
                    this.mType = Type.FALSE;
                    isValid = true;
                    break;
                } else if (this.mTokenNull[this.mIndex] == c) {
                    this.mType = Type.NULL;
                    isValid = true;
                    break;
                }
                break;
            case TRUE:
                isValid = this.mTokenTrue[this.mIndex] == c;
                if (isValid && this.mIndex + 1 == this.mTokenTrue.length) {
                    setEnd(position);
                    break;
                }
                break;
            case FALSE:
                isValid = this.mTokenFalse[this.mIndex] == c;
                if (isValid && this.mIndex + 1 == this.mTokenFalse.length) {
                    setEnd(position);
                    break;
                }
                break;
            case NULL:
                isValid = this.mTokenNull[this.mIndex] == c;
                if (isValid && this.mIndex + 1 == this.mTokenNull.length) {
                    setEnd(position);
                    break;
                }
                break;
        }
        this.mIndex++;
        return isValid;
    }
}
