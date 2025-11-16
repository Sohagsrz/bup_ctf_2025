package androidx.constraintlayout.core.parser;

import java.util.Arrays;
import java.util.Objects;

/* loaded from: classes.dex */
public class CLElement implements Cloneable {
    protected CLContainer mContainer;
    private final char[] mContent;
    private int mLine;
    protected static int sMaxLine = 80;
    protected static int sBaseIndent = 2;
    protected long mStart = -1;
    protected long mEnd = Long.MAX_VALUE;

    public CLElement(char[] content) {
        this.mContent = content;
    }

    public boolean notStarted() {
        return this.mStart == -1;
    }

    public void setLine(int line) {
        this.mLine = line;
    }

    public int getLine() {
        return this.mLine;
    }

    public void setStart(long start) {
        this.mStart = start;
    }

    public long getStart() {
        return this.mStart;
    }

    public long getEnd() {
        return this.mEnd;
    }

    public void setEnd(long end) {
        if (this.mEnd != Long.MAX_VALUE) {
            return;
        }
        this.mEnd = end;
        if (CLParser.sDebug) {
            System.out.println("closing " + hashCode() + " -> " + this);
        }
        if (this.mContainer != null) {
            this.mContainer.add(this);
        }
    }

    protected void addIndent(StringBuilder builder, int indent) {
        for (int i = 0; i < indent; i++) {
            builder.append(' ');
        }
    }

    public String toString() {
        if (this.mStart > this.mEnd || this.mEnd == Long.MAX_VALUE) {
            return getClass() + " (INVALID, " + this.mStart + "-" + this.mEnd + ")";
        }
        String content = new String(this.mContent);
        return getStrClass() + " (" + this.mStart + " : " + this.mEnd + ") <<" + content.substring((int) this.mStart, ((int) this.mEnd) + 1) + ">>";
    }

    protected String getStrClass() {
        String myClass = getClass().toString();
        return myClass.substring(myClass.lastIndexOf(46) + 1);
    }

    protected String getDebugName() {
        if (CLParser.sDebug) {
            return getStrClass() + " -> ";
        }
        return "";
    }

    public String content() {
        String content = new String(this.mContent);
        if (content.length() < 1) {
            return "";
        }
        if (this.mEnd == Long.MAX_VALUE || this.mEnd < this.mStart) {
            return content.substring((int) this.mStart, ((int) this.mStart) + 1);
        }
        return content.substring((int) this.mStart, ((int) this.mEnd) + 1);
    }

    public boolean hasContent() {
        return this.mContent != null && this.mContent.length >= 1;
    }

    public boolean isDone() {
        return this.mEnd != Long.MAX_VALUE;
    }

    public void setContainer(CLContainer element) {
        this.mContainer = element;
    }

    public CLElement getContainer() {
        return this.mContainer;
    }

    public boolean isStarted() {
        return this.mStart > -1;
    }

    protected String toJSON() {
        return "";
    }

    protected String toFormattedJSON(int indent, int forceIndent) {
        return "";
    }

    public int getInt() {
        if (this instanceof CLNumber) {
            return ((CLNumber) this).getInt();
        }
        return 0;
    }

    public float getFloat() {
        if (this instanceof CLNumber) {
            return ((CLNumber) this).getFloat();
        }
        return Float.NaN;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CLElement)) {
            return false;
        }
        CLElement clElement = (CLElement) o;
        if (this.mStart == clElement.mStart && this.mEnd == clElement.mEnd && this.mLine == clElement.mLine && Arrays.equals(this.mContent, clElement.mContent)) {
            return Objects.equals(this.mContainer, clElement.mContainer);
        }
        return false;
    }

    public int hashCode() {
        int result = Arrays.hashCode(this.mContent);
        return (((((((result * 31) + ((int) (this.mStart ^ (this.mStart >>> 32)))) * 31) + ((int) (this.mEnd ^ (this.mEnd >>> 32)))) * 31) + (this.mContainer != null ? this.mContainer.hashCode() : 0)) * 31) + this.mLine;
    }

    @Override // 
    /* renamed from: clone, reason: merged with bridge method [inline-methods] */
    public CLElement mo12clone() {
        try {
            return (CLElement) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError();
        }
    }
}
