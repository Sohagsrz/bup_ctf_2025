package androidx.constraintlayout.core.parser;

import androidx.constraintlayout.widget.ConstraintLayout;

/* loaded from: classes.dex */
public class CLParser {
    static boolean sDebug = false;
    private String mContent;
    private boolean mHasComment = false;
    private int mLineNumber;

    enum TYPE {
        UNKNOWN,
        OBJECT,
        ARRAY,
        NUMBER,
        STRING,
        KEY,
        TOKEN
    }

    public static CLObject parse(String string) throws CLParsingException {
        return new CLParser(string).parse();
    }

    public CLParser(String content) {
        this.mContent = content;
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x01a9, code lost:
    
        if (androidx.constraintlayout.core.parser.CLParser.sDebug == false) goto L102;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x01ab, code lost:
    
        java.lang.System.out.println("Root: " + r1.toJSON());
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x01c7, code lost:
    
        return r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x0188, code lost:
    
        if (r3 == null) goto L116;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x018e, code lost:
    
        if (r3.isDone() != false) goto L117;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x0192, code lost:
    
        if ((r3 instanceof androidx.constraintlayout.core.parser.CLString) == false) goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x0194, code lost:
    
        r3.setStart(((int) r3.mStart) + r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x019c, code lost:
    
        r3.setEnd(r4 - 1);
        r3 = r3.getContainer();
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public androidx.constraintlayout.core.parser.CLObject parse() throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 467
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.parser.CLParser.parse():androidx.constraintlayout.core.parser.CLObject");
    }

    private CLElement getNextJsonElement(int position, char c, CLElement currentElement, char[] content) throws CLParsingException {
        CLElement currentElement2;
        switch (c) {
            case '\t':
            case '\n':
            case '\r':
            case ' ':
            case ',':
            case ':':
                currentElement2 = currentElement;
                break;
            case '\"':
            case '\'':
                return currentElement instanceof CLObject ? createElement(currentElement, position, TYPE.KEY, true, content) : createElement(currentElement, position, TYPE.STRING, true, content);
            case '+':
            case '-':
            case '.':
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE /* 48 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_EDITOR_ABSOLUTEX /* 49 */:
            case '2':
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_TAG /* 51 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_BASELINE_TO_TOP_OF /* 52 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_BASELINE_TO_BOTTOM_OF /* 53 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_MARGIN_BASELINE /* 54 */:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_GONE_MARGIN_BASELINE /* 55 */:
            case '8':
            case '9':
                return createElement(currentElement, position, TYPE.NUMBER, true, content);
            case '/':
                currentElement2 = currentElement;
                if (position + 1 < content.length && content[position + 1] == '/') {
                    this.mHasComment = true;
                    break;
                }
                break;
            case '[':
                return createElement(currentElement, position, TYPE.ARRAY, true, content);
            case ']':
            case '}':
                currentElement.setEnd(position - 1);
                CLElement currentElement3 = currentElement.getContainer();
                currentElement3.setEnd(position);
                return currentElement3;
            case '{':
                return createElement(currentElement, position, TYPE.OBJECT, true, content);
            default:
                if (!(currentElement instanceof CLContainer) || (currentElement instanceof CLObject)) {
                    return createElement(currentElement, position, TYPE.KEY, true, content);
                }
                CLElement currentElement4 = createElement(currentElement, position, TYPE.TOKEN, true, content);
                CLToken token = (CLToken) currentElement4;
                if (!token.validate(c, position)) {
                    throw new CLParsingException("incorrect token <" + c + "> at line " + this.mLineNumber, token);
                }
                return currentElement4;
        }
        return currentElement2;
    }

    private CLElement createElement(CLElement currentElement, int position, TYPE type, boolean applyStart, char[] content) {
        CLElement newElement = null;
        if (sDebug) {
            System.out.println("CREATE " + type + " at " + content[position]);
        }
        switch (type.ordinal()) {
            case 1:
                newElement = CLObject.allocate(content);
                position++;
                break;
            case 2:
                newElement = CLArray.allocate(content);
                position++;
                break;
            case 3:
                newElement = CLNumber.allocate(content);
                break;
            case 4:
                newElement = CLString.allocate(content);
                break;
            case 5:
                newElement = CLKey.allocate(content);
                break;
            case 6:
                newElement = CLToken.allocate(content);
                break;
        }
        if (newElement == null) {
            return null;
        }
        newElement.setLine(this.mLineNumber);
        if (applyStart) {
            newElement.setStart(position);
        }
        if (currentElement instanceof CLContainer) {
            CLContainer container = (CLContainer) currentElement;
            newElement.setContainer(container);
        }
        return newElement;
    }
}
