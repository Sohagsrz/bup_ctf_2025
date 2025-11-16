package androidx.constraintlayout.core.dsl;

import androidx.constraintlayout.core.dsl.Constraint;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public class Helper {
    protected static final Map<Constraint.Side, String> sideMap = new HashMap();
    protected static final Map<Type, String> typeMap;
    protected String config;
    protected Map<String, String> configMap;
    protected final String name;
    protected HelperType type;

    public enum Type {
        VERTICAL_GUIDELINE,
        HORIZONTAL_GUIDELINE,
        VERTICAL_CHAIN,
        HORIZONTAL_CHAIN,
        BARRIER
    }

    static {
        sideMap.put(Constraint.Side.LEFT, "'left'");
        sideMap.put(Constraint.Side.RIGHT, "'right'");
        sideMap.put(Constraint.Side.TOP, "'top'");
        sideMap.put(Constraint.Side.BOTTOM, "'bottom'");
        sideMap.put(Constraint.Side.START, "'start'");
        sideMap.put(Constraint.Side.END, "'end'");
        sideMap.put(Constraint.Side.BASELINE, "'baseline'");
        typeMap = new HashMap();
        typeMap.put(Type.VERTICAL_GUIDELINE, "vGuideline");
        typeMap.put(Type.HORIZONTAL_GUIDELINE, "hGuideline");
        typeMap.put(Type.VERTICAL_CHAIN, "vChain");
        typeMap.put(Type.HORIZONTAL_CHAIN, "hChain");
        typeMap.put(Type.BARRIER, "barrier");
    }

    public Helper(String name, HelperType type) {
        this.type = null;
        this.configMap = new HashMap();
        this.name = name;
        this.type = type;
    }

    public Helper(String name, HelperType type, String config) {
        this.type = null;
        this.configMap = new HashMap();
        this.name = name;
        this.type = type;
        this.config = config;
        this.configMap = convertConfigToMap();
    }

    public String getId() {
        return this.name;
    }

    public HelperType getType() {
        return this.type;
    }

    public String getConfig() {
        return this.config;
    }

    public Map<String, String> convertConfigToMap() {
        if (this.config == null || this.config.length() == 0) {
            return null;
        }
        Map<String, String> map = new HashMap<>();
        StringBuilder builder = new StringBuilder();
        String key = "";
        int squareBrackets = 0;
        int curlyBrackets = 0;
        for (int i = 0; i < this.config.length(); i++) {
            char ch = this.config.charAt(i);
            if (ch == ':') {
                key = builder.toString();
                builder.setLength(0);
            } else if (ch == ',' && squareBrackets == 0 && curlyBrackets == 0) {
                String value = builder.toString();
                map.put(key, value);
                builder.setLength(0);
                key = "";
            } else if (ch != ' ') {
                switch (ch) {
                    case '[':
                        squareBrackets++;
                        break;
                    case ']':
                        squareBrackets--;
                        break;
                    case '{':
                        curlyBrackets++;
                        break;
                    case '}':
                        curlyBrackets--;
                        break;
                }
                builder.append(ch);
            }
        }
        map.put(key, builder.toString());
        return map;
    }

    public void append(Map<String, String> map, StringBuilder ret) {
        if (map.isEmpty()) {
            return;
        }
        for (String key : map.keySet()) {
            ret.append(key).append(":").append(map.get(key)).append(",\n");
        }
    }

    public String toString() {
        StringBuilder ret = new StringBuilder(this.name + ":{\n");
        if (this.type != null) {
            ret.append("type:'").append(this.type.toString()).append("',\n");
        }
        if (this.configMap != null) {
            append(this.configMap, ret);
        }
        ret.append("},\n");
        return ret.toString();
    }

    public static void main(String[] args) {
        Barrier b = new Barrier("abc", "['a1', 'b2']");
        System.out.println(b.toString());
    }

    public static final class HelperType {
        final String mName;

        public HelperType(String str) {
            this.mName = str;
        }

        public String toString() {
            return this.mName;
        }
    }
}
