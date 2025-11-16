package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.core.state.HelperReference;
import androidx.constraintlayout.core.state.State;
import androidx.constraintlayout.core.utils.GridCore;
import androidx.constraintlayout.core.widgets.HelperWidget;

/* loaded from: classes.dex */
public class GridReference extends HelperReference {
    private static final String SPANS_RESPECT_WIDGET_ORDER_STRING = "spansrespectwidgetorder";
    private static final String SUB_GRID_BY_COL_ROW_STRING = "subgridbycolrow";
    private String mColumnWeights;
    private int mColumnsSet;
    private int mFlags;
    private GridCore mGrid;
    private float mHorizontalGaps;
    private int mOrientation;
    private int mPaddingBottom;
    private int mPaddingEnd;
    private int mPaddingStart;
    private int mPaddingTop;
    private String mRowWeights;
    private int mRowsSet;
    private String mSkips;
    private String mSpans;
    private float mVerticalGaps;

    public GridReference(State state, State.Helper type) {
        super(state, type);
        this.mPaddingStart = 0;
        this.mPaddingEnd = 0;
        this.mPaddingTop = 0;
        this.mPaddingBottom = 0;
        if (type == State.Helper.ROW) {
            this.mRowsSet = 1;
        } else if (type == State.Helper.COLUMN) {
            this.mColumnsSet = 1;
        }
    }

    public int getPaddingStart() {
        return this.mPaddingStart;
    }

    public void setPaddingStart(int paddingStart) {
        this.mPaddingStart = paddingStart;
    }

    public int getPaddingEnd() {
        return this.mPaddingEnd;
    }

    public void setPaddingEnd(int paddingEnd) {
        this.mPaddingEnd = paddingEnd;
    }

    public int getPaddingTop() {
        return this.mPaddingTop;
    }

    public void setPaddingTop(int paddingTop) {
        this.mPaddingTop = paddingTop;
    }

    public int getPaddingBottom() {
        return this.mPaddingBottom;
    }

    public void setPaddingBottom(int paddingBottom) {
        this.mPaddingBottom = paddingBottom;
    }

    public int getFlags() {
        return this.mFlags;
    }

    public void setFlags(int flags) {
        this.mFlags = flags;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0039  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setFlags(java.lang.String r9) {
        /*
            r8 = this;
            boolean r0 = r9.isEmpty()
            if (r0 == 0) goto L7
            return
        L7:
            java.lang.String r0 = "\\|"
            java.lang.String[] r0 = r9.split(r0)
            r1 = 0
            r8.mFlags = r1
            int r2 = r0.length
            r3 = r1
        L12:
            if (r3 >= r2) goto L4e
            r4 = r0[r3]
            java.lang.String r5 = r4.toLowerCase()
            int r6 = r5.hashCode()
            r7 = 1
            switch(r6) {
                case -578405641: goto L2e;
                case 2144989229: goto L23;
                default: goto L22;
            }
        L22:
            goto L39
        L23:
            java.lang.String r6 = "spansrespectwidgetorder"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L22
            r5 = r7
            goto L3a
        L2e:
            java.lang.String r6 = "subgridbycolrow"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L22
            r5 = r1
            goto L3a
        L39:
            r5 = -1
        L3a:
            switch(r5) {
                case 0: goto L45;
                case 1: goto L3e;
                default: goto L3d;
            }
        L3d:
            goto L4b
        L3e:
            int r5 = r8.mFlags
            r5 = r5 | 2
            r8.mFlags = r5
            goto L4b
        L45:
            int r5 = r8.mFlags
            r5 = r5 | r7
            r8.mFlags = r5
        L4b:
            int r3 = r3 + 1
            goto L12
        L4e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.helpers.GridReference.setFlags(java.lang.String):void");
    }

    public int getRowsSet() {
        return this.mRowsSet;
    }

    public void setRowsSet(int rowsSet) {
        if (super.getType() == State.Helper.COLUMN) {
            return;
        }
        this.mRowsSet = rowsSet;
    }

    public int getColumnsSet() {
        return this.mColumnsSet;
    }

    public void setColumnsSet(int columnsSet) {
        if (super.getType() == State.Helper.ROW) {
            return;
        }
        this.mColumnsSet = columnsSet;
    }

    public float getHorizontalGaps() {
        return this.mHorizontalGaps;
    }

    public void setHorizontalGaps(float horizontalGaps) {
        this.mHorizontalGaps = horizontalGaps;
    }

    public float getVerticalGaps() {
        return this.mVerticalGaps;
    }

    public void setVerticalGaps(float verticalGaps) {
        this.mVerticalGaps = verticalGaps;
    }

    public String getRowWeights() {
        return this.mRowWeights;
    }

    public void setRowWeights(String rowWeights) {
        this.mRowWeights = rowWeights;
    }

    public String getColumnWeights() {
        return this.mColumnWeights;
    }

    public void setColumnWeights(String columnWeights) {
        this.mColumnWeights = columnWeights;
    }

    public String getSpans() {
        return this.mSpans;
    }

    public void setSpans(String spans) {
        this.mSpans = spans;
    }

    public String getSkips() {
        return this.mSkips;
    }

    public void setSkips(String skips) {
        this.mSkips = skips;
    }

    @Override // androidx.constraintlayout.core.state.HelperReference
    public HelperWidget getHelperWidget() {
        if (this.mGrid == null) {
            this.mGrid = new GridCore();
        }
        return this.mGrid;
    }

    @Override // androidx.constraintlayout.core.state.HelperReference
    public void setHelperWidget(HelperWidget widget) {
        if (widget instanceof GridCore) {
            this.mGrid = (GridCore) widget;
        } else {
            this.mGrid = null;
        }
    }

    public int getOrientation() {
        return this.mOrientation;
    }

    public void setOrientation(int orientation) {
        this.mOrientation = orientation;
    }

    @Override // androidx.constraintlayout.core.state.HelperReference, androidx.constraintlayout.core.state.ConstraintReference, androidx.constraintlayout.core.state.Reference
    public void apply() {
        getHelperWidget();
        this.mGrid.setOrientation(this.mOrientation);
        if (this.mRowsSet != 0) {
            this.mGrid.setRows(this.mRowsSet);
        }
        if (this.mColumnsSet != 0) {
            this.mGrid.setColumns(this.mColumnsSet);
        }
        if (this.mHorizontalGaps != 0.0f) {
            this.mGrid.setHorizontalGaps(this.mHorizontalGaps);
        }
        if (this.mVerticalGaps != 0.0f) {
            this.mGrid.setVerticalGaps(this.mVerticalGaps);
        }
        if (this.mRowWeights != null && !this.mRowWeights.isEmpty()) {
            this.mGrid.setRowWeights(this.mRowWeights);
        }
        if (this.mColumnWeights != null && !this.mColumnWeights.isEmpty()) {
            this.mGrid.setColumnWeights(this.mColumnWeights);
        }
        if (this.mSpans != null && !this.mSpans.isEmpty()) {
            this.mGrid.setSpans(this.mSpans);
        }
        if (this.mSkips != null && !this.mSkips.isEmpty()) {
            this.mGrid.setSkips(this.mSkips);
        }
        this.mGrid.setFlags(this.mFlags);
        this.mGrid.setPaddingStart(this.mPaddingStart);
        this.mGrid.setPaddingEnd(this.mPaddingEnd);
        this.mGrid.setPaddingTop(this.mPaddingTop);
        this.mGrid.setPaddingBottom(this.mPaddingBottom);
        applyBase();
    }
}
