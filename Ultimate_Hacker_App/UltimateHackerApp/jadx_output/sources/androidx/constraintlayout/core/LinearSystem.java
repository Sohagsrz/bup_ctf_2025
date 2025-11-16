package androidx.constraintlayout.core;

import androidx.constraintlayout.core.SolverVariable;
import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import java.util.Arrays;
import java.util.HashMap;

/* loaded from: classes.dex */
public class LinearSystem {
    public static final boolean DEBUG = false;
    private static final boolean DEBUG_CONSTRAINTS = false;
    private static final boolean DO_NOT_USE = false;
    public static final boolean FULL_DEBUG = false;
    public static Metrics sMetrics;
    final Cache mCache;
    private Row mGoal;
    ArrayRow[] mRows;
    private Row mTempGoal;
    public static boolean USE_DEPENDENCY_ORDERING = false;
    public static boolean USE_BASIC_SYNONYMS = true;
    public static boolean SIMPLIFY_SYNONYMS = true;
    public static boolean USE_SYNONYMS = true;
    public static boolean SKIP_COLUMNS = true;
    public static boolean OPTIMIZED_ENGINE = false;
    public static long ARRAY_ROW_CREATION = 0;
    public static long OPTIMIZED_ARRAY_ROW_CREATION = 0;
    private int mPoolSize = 1000;
    public boolean hasSimpleDefinition = false;
    int mVariablesID = 0;
    private HashMap<String, SolverVariable> mVariables = null;
    private int mTableSize = 32;
    private int mMaxColumns = this.mTableSize;
    public boolean graphOptimizer = false;
    public boolean newgraphOptimizer = false;
    private boolean[] mAlreadyTestedCandidates = new boolean[this.mTableSize];
    int mNumColumns = 1;
    int mNumRows = 0;
    private int mMaxRows = this.mTableSize;
    private SolverVariable[] mPoolVariables = new SolverVariable[this.mPoolSize];
    private int mPoolVariablesCount = 0;

    interface Row {
        void addError(SolverVariable solverVariable);

        void clear();

        SolverVariable getKey();

        SolverVariable getPivotCandidate(LinearSystem linearSystem, boolean[] zArr);

        void initFromRow(Row row);

        boolean isEmpty();

        void updateFromFinalVariable(LinearSystem linearSystem, SolverVariable solverVariable, boolean z);

        void updateFromRow(LinearSystem linearSystem, ArrayRow arrayRow, boolean z);

        void updateFromSystem(LinearSystem linearSystem);
    }

    static class ValuesRow extends ArrayRow {
        ValuesRow(Cache cache) {
            this.variables = new SolverVariableValues(this, cache);
        }
    }

    public LinearSystem() {
        this.mRows = null;
        this.mRows = new ArrayRow[this.mTableSize];
        releaseRows();
        this.mCache = new Cache();
        this.mGoal = new PriorityGoalRow(this.mCache);
        if (OPTIMIZED_ENGINE) {
            this.mTempGoal = new ValuesRow(this.mCache);
        } else {
            this.mTempGoal = new ArrayRow(this.mCache);
        }
    }

    public void fillMetrics(Metrics metrics) {
        sMetrics = metrics;
    }

    public static Metrics getMetrics() {
        return sMetrics;
    }

    private void increaseTableSize() {
        this.mTableSize *= 2;
        this.mRows = (ArrayRow[]) Arrays.copyOf(this.mRows, this.mTableSize);
        this.mCache.mIndexedVariables = (SolverVariable[]) Arrays.copyOf(this.mCache.mIndexedVariables, this.mTableSize);
        this.mAlreadyTestedCandidates = new boolean[this.mTableSize];
        this.mMaxColumns = this.mTableSize;
        this.mMaxRows = this.mTableSize;
        if (sMetrics != null) {
            sMetrics.tableSizeIncrease++;
            sMetrics.maxTableSize = Math.max(sMetrics.maxTableSize, this.mTableSize);
            sMetrics.lastTableSize = sMetrics.maxTableSize;
        }
    }

    private void releaseRows() {
        if (OPTIMIZED_ENGINE) {
            for (int i = 0; i < this.mNumRows; i++) {
                ArrayRow row = this.mRows[i];
                if (row != null) {
                    this.mCache.mOptimizedArrayRowPool.release(row);
                }
                this.mRows[i] = null;
            }
            return;
        }
        for (int i2 = 0; i2 < this.mNumRows; i2++) {
            ArrayRow row2 = this.mRows[i2];
            if (row2 != null) {
                this.mCache.mArrayRowPool.release(row2);
            }
            this.mRows[i2] = null;
        }
    }

    public void reset() {
        for (int i = 0; i < this.mCache.mIndexedVariables.length; i++) {
            SolverVariable variable = this.mCache.mIndexedVariables[i];
            if (variable != null) {
                variable.reset();
            }
        }
        this.mCache.mSolverVariablePool.releaseAll(this.mPoolVariables, this.mPoolVariablesCount);
        this.mPoolVariablesCount = 0;
        Arrays.fill(this.mCache.mIndexedVariables, (Object) null);
        if (this.mVariables != null) {
            this.mVariables.clear();
        }
        this.mVariablesID = 0;
        this.mGoal.clear();
        this.mNumColumns = 1;
        for (int i2 = 0; i2 < this.mNumRows; i2++) {
            if (this.mRows[i2] != null) {
                this.mRows[i2].mUsed = false;
            }
        }
        releaseRows();
        this.mNumRows = 0;
        if (OPTIMIZED_ENGINE) {
            this.mTempGoal = new ValuesRow(this.mCache);
        } else {
            this.mTempGoal = new ArrayRow(this.mCache);
        }
    }

    public SolverVariable createObjectVariable(Object anchor) {
        if (anchor == null) {
            return null;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = null;
        if (anchor instanceof ConstraintAnchor) {
            variable = ((ConstraintAnchor) anchor).getSolverVariable();
            if (variable == null) {
                ((ConstraintAnchor) anchor).resetSolverVariable(this.mCache);
                variable = ((ConstraintAnchor) anchor).getSolverVariable();
            }
            if (variable.id == -1 || variable.id > this.mVariablesID || this.mCache.mIndexedVariables[variable.id] == null) {
                if (variable.id != -1) {
                    variable.reset();
                }
                this.mVariablesID++;
                this.mNumColumns++;
                variable.id = this.mVariablesID;
                variable.mType = SolverVariable.Type.UNRESTRICTED;
                this.mCache.mIndexedVariables[this.mVariablesID] = variable;
            }
        }
        return variable;
    }

    public ArrayRow createRow() {
        ArrayRow row;
        if (OPTIMIZED_ENGINE) {
            row = this.mCache.mOptimizedArrayRowPool.acquire();
            if (row == null) {
                row = new ValuesRow(this.mCache);
                OPTIMIZED_ARRAY_ROW_CREATION++;
            } else {
                row.reset();
            }
        } else {
            row = this.mCache.mArrayRowPool.acquire();
            if (row == null) {
                row = new ArrayRow(this.mCache);
                ARRAY_ROW_CREATION++;
            } else {
                row.reset();
            }
        }
        SolverVariable.increaseErrorId();
        return row;
    }

    public SolverVariable createSlackVariable() {
        if (sMetrics != null) {
            sMetrics.slackvariables++;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = acquireSolverVariable(SolverVariable.Type.SLACK, null);
        this.mVariablesID++;
        this.mNumColumns++;
        variable.id = this.mVariablesID;
        this.mCache.mIndexedVariables[this.mVariablesID] = variable;
        return variable;
    }

    public SolverVariable createExtraVariable() {
        if (sMetrics != null) {
            sMetrics.extravariables++;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = acquireSolverVariable(SolverVariable.Type.SLACK, null);
        this.mVariablesID++;
        this.mNumColumns++;
        variable.id = this.mVariablesID;
        this.mCache.mIndexedVariables[this.mVariablesID] = variable;
        return variable;
    }

    void addSingleError(ArrayRow row, int sign, int strength) {
        SolverVariable error = createErrorVariable(strength, null);
        row.addSingleError(error, sign);
    }

    private SolverVariable createVariable(String name, SolverVariable.Type type) {
        if (sMetrics != null) {
            sMetrics.variables++;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = acquireSolverVariable(type, null);
        variable.setName(name);
        this.mVariablesID++;
        this.mNumColumns++;
        variable.id = this.mVariablesID;
        if (this.mVariables == null) {
            this.mVariables = new HashMap<>();
        }
        this.mVariables.put(name, variable);
        this.mCache.mIndexedVariables[this.mVariablesID] = variable;
        return variable;
    }

    public SolverVariable createErrorVariable(int strength, String prefix) {
        if (sMetrics != null) {
            sMetrics.errors++;
        }
        if (this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        SolverVariable variable = acquireSolverVariable(SolverVariable.Type.ERROR, prefix);
        this.mVariablesID++;
        this.mNumColumns++;
        variable.id = this.mVariablesID;
        variable.strength = strength;
        this.mCache.mIndexedVariables[this.mVariablesID] = variable;
        this.mGoal.addError(variable);
        return variable;
    }

    private SolverVariable acquireSolverVariable(SolverVariable.Type type, String prefix) {
        SolverVariable variable = this.mCache.mSolverVariablePool.acquire();
        if (variable == null) {
            variable = new SolverVariable(type, prefix);
            variable.setType(type, prefix);
        } else {
            variable.reset();
            variable.setType(type, prefix);
        }
        if (this.mPoolVariablesCount >= this.mPoolSize) {
            this.mPoolSize *= 2;
            this.mPoolVariables = (SolverVariable[]) Arrays.copyOf(this.mPoolVariables, this.mPoolSize);
        }
        SolverVariable[] solverVariableArr = this.mPoolVariables;
        int i = this.mPoolVariablesCount;
        this.mPoolVariablesCount = i + 1;
        solverVariableArr[i] = variable;
        return variable;
    }

    Row getGoal() {
        return this.mGoal;
    }

    ArrayRow getRow(int n) {
        return this.mRows[n];
    }

    float getValueFor(String name) {
        SolverVariable v = getVariable(name, SolverVariable.Type.UNRESTRICTED);
        if (v == null) {
            return 0.0f;
        }
        return v.computedValue;
    }

    public int getObjectVariableValue(Object object) {
        ConstraintAnchor anchor = (ConstraintAnchor) object;
        SolverVariable variable = anchor.getSolverVariable();
        if (variable != null) {
            return (int) (variable.computedValue + 0.5f);
        }
        return 0;
    }

    SolverVariable getVariable(String name, SolverVariable.Type type) {
        if (this.mVariables == null) {
            this.mVariables = new HashMap<>();
        }
        SolverVariable variable = this.mVariables.get(name);
        if (variable == null) {
            return createVariable(name, type);
        }
        return variable;
    }

    public void minimize() throws Exception {
        if (sMetrics != null) {
            sMetrics.minimize++;
        }
        if (this.mGoal.isEmpty()) {
            computeValues();
            return;
        }
        if (this.graphOptimizer || this.newgraphOptimizer) {
            if (sMetrics != null) {
                sMetrics.graphOptimizer++;
            }
            boolean fullySolved = true;
            int i = 0;
            while (true) {
                if (i >= this.mNumRows) {
                    break;
                }
                ArrayRow r = this.mRows[i];
                if (r.mIsSimpleDefinition) {
                    i++;
                } else {
                    fullySolved = false;
                    break;
                }
            }
            if (!fullySolved) {
                minimizeGoal(this.mGoal);
                return;
            }
            if (sMetrics != null) {
                sMetrics.fullySolved++;
            }
            computeValues();
            return;
        }
        minimizeGoal(this.mGoal);
    }

    void minimizeGoal(Row goal) throws Exception {
        if (sMetrics != null) {
            sMetrics.minimizeGoal++;
            sMetrics.maxVariables = Math.max(sMetrics.maxVariables, this.mNumColumns);
            sMetrics.maxRows = Math.max(sMetrics.maxRows, this.mNumRows);
        }
        enforceBFS(goal);
        optimize(goal, false);
        computeValues();
    }

    final void cleanupRows() {
        int i = 0;
        while (i < this.mNumRows) {
            ArrayRow current = this.mRows[i];
            if (current.variables.getCurrentSize() == 0) {
                current.mIsSimpleDefinition = true;
            }
            if (current.mIsSimpleDefinition) {
                current.mVariable.computedValue = current.mConstantValue;
                current.mVariable.removeFromRow(current);
                for (int j = i; j < this.mNumRows - 1; j++) {
                    this.mRows[j] = this.mRows[j + 1];
                }
                this.mRows[this.mNumRows - 1] = null;
                this.mNumRows--;
                i--;
                if (OPTIMIZED_ENGINE) {
                    this.mCache.mOptimizedArrayRowPool.release(current);
                } else {
                    this.mCache.mArrayRowPool.release(current);
                }
            }
            i++;
        }
    }

    public void addConstraint(ArrayRow row) {
        SolverVariable pivotCandidate;
        if (row == null) {
            return;
        }
        if (sMetrics != null) {
            sMetrics.constraints++;
            if (row.mIsSimpleDefinition) {
                sMetrics.simpleconstraints++;
            }
        }
        if (this.mNumRows + 1 >= this.mMaxRows || this.mNumColumns + 1 >= this.mMaxColumns) {
            increaseTableSize();
        }
        boolean added = false;
        if (!row.mIsSimpleDefinition) {
            row.updateFromSystem(this);
            if (row.isEmpty()) {
                return;
            }
            row.ensurePositiveConstant();
            if (row.chooseSubject(this)) {
                SolverVariable extra = createExtraVariable();
                row.mVariable = extra;
                int numRows = this.mNumRows;
                addRow(row);
                if (this.mNumRows == numRows + 1) {
                    added = true;
                    this.mTempGoal.initFromRow(row);
                    optimize(this.mTempGoal, true);
                    if (extra.mDefinitionId == -1) {
                        if (row.mVariable == extra && (pivotCandidate = row.pickPivot(extra)) != null) {
                            if (sMetrics != null) {
                                sMetrics.pivots++;
                            }
                            row.pivot(pivotCandidate);
                        }
                        if (!row.mIsSimpleDefinition) {
                            row.mVariable.updateReferencesWithNewDefinition(this, row);
                        }
                        if (OPTIMIZED_ENGINE) {
                            this.mCache.mOptimizedArrayRowPool.release(row);
                        } else {
                            this.mCache.mArrayRowPool.release(row);
                        }
                        this.mNumRows--;
                    }
                }
            }
            if (!row.hasKeyVariable()) {
                return;
            }
        }
        if (!added) {
            addRow(row);
        }
    }

    private void addRow(ArrayRow row) {
        if (SIMPLIFY_SYNONYMS && row.mIsSimpleDefinition) {
            row.mVariable.setFinalValue(this, row.mConstantValue);
        } else {
            this.mRows[this.mNumRows] = row;
            row.mVariable.mDefinitionId = this.mNumRows;
            this.mNumRows++;
            row.mVariable.updateReferencesWithNewDefinition(this, row);
        }
        if (SIMPLIFY_SYNONYMS && this.hasSimpleDefinition) {
            int i = 0;
            while (i < this.mNumRows) {
                if (this.mRows[i] == null) {
                    System.out.println("WTF");
                }
                if (this.mRows[i] != null && this.mRows[i].mIsSimpleDefinition) {
                    ArrayRow removedRow = this.mRows[i];
                    removedRow.mVariable.setFinalValue(this, removedRow.mConstantValue);
                    if (OPTIMIZED_ENGINE) {
                        this.mCache.mOptimizedArrayRowPool.release(removedRow);
                    } else {
                        this.mCache.mArrayRowPool.release(removedRow);
                    }
                    this.mRows[i] = null;
                    int lastRow = i + 1;
                    for (int j = i + 1; j < this.mNumRows; j++) {
                        this.mRows[j - 1] = this.mRows[j];
                        if (this.mRows[j - 1].mVariable.mDefinitionId == j) {
                            this.mRows[j - 1].mVariable.mDefinitionId = j - 1;
                        }
                        lastRow = j;
                    }
                    int j2 = this.mNumRows;
                    if (lastRow < j2) {
                        this.mRows[lastRow] = null;
                    }
                    this.mNumRows--;
                    i--;
                }
                i++;
            }
            this.hasSimpleDefinition = false;
        }
    }

    public void removeRow(ArrayRow row) {
        if (row.mIsSimpleDefinition && row.mVariable != null) {
            if (row.mVariable.mDefinitionId != -1) {
                for (int i = row.mVariable.mDefinitionId; i < this.mNumRows - 1; i++) {
                    SolverVariable rowVariable = this.mRows[i + 1].mVariable;
                    if (rowVariable.mDefinitionId == i + 1) {
                        rowVariable.mDefinitionId = i;
                    }
                    this.mRows[i] = this.mRows[i + 1];
                }
                int i2 = this.mNumRows;
                this.mNumRows = i2 - 1;
            }
            if (!row.mVariable.isFinalValue) {
                row.mVariable.setFinalValue(this, row.mConstantValue);
            }
            if (OPTIMIZED_ENGINE) {
                this.mCache.mOptimizedArrayRowPool.release(row);
            } else {
                this.mCache.mArrayRowPool.release(row);
            }
        }
    }

    private int optimize(Row goal, boolean b) {
        if (sMetrics != null) {
            sMetrics.optimize++;
        }
        boolean done = false;
        int tries = 0;
        for (int i = 0; i < this.mNumColumns; i++) {
            this.mAlreadyTestedCandidates[i] = false;
        }
        while (!done) {
            if (sMetrics != null) {
                sMetrics.iterations++;
            }
            tries++;
            if (tries >= this.mNumColumns * 2) {
                return tries;
            }
            if (goal.getKey() != null) {
                this.mAlreadyTestedCandidates[goal.getKey().id] = true;
            }
            SolverVariable pivotCandidate = goal.getPivotCandidate(this, this.mAlreadyTestedCandidates);
            if (pivotCandidate != null) {
                if (this.mAlreadyTestedCandidates[pivotCandidate.id]) {
                    return tries;
                }
                this.mAlreadyTestedCandidates[pivotCandidate.id] = true;
            }
            if (pivotCandidate != null) {
                float min = Float.MAX_VALUE;
                int pivotRowIndex = -1;
                for (int i2 = 0; i2 < this.mNumRows; i2++) {
                    ArrayRow current = this.mRows[i2];
                    SolverVariable variable = current.mVariable;
                    if (variable.mType != SolverVariable.Type.UNRESTRICTED && !current.mIsSimpleDefinition && current.hasVariable(pivotCandidate)) {
                        float a_j = current.variables.get(pivotCandidate);
                        if (a_j < 0.0f) {
                            float value = (-current.mConstantValue) / a_j;
                            if (value < min) {
                                min = value;
                                pivotRowIndex = i2;
                            }
                        }
                    }
                }
                if (pivotRowIndex > -1) {
                    ArrayRow pivotEquation = this.mRows[pivotRowIndex];
                    pivotEquation.mVariable.mDefinitionId = -1;
                    if (sMetrics != null) {
                        sMetrics.pivots++;
                    }
                    pivotEquation.pivot(pivotCandidate);
                    pivotEquation.mVariable.mDefinitionId = pivotRowIndex;
                    pivotEquation.mVariable.updateReferencesWithNewDefinition(this, pivotEquation);
                }
            } else {
                done = true;
            }
        }
        return tries;
    }

    private int enforceBFS(Row goal) throws Exception {
        float f;
        boolean infeasibleSystem;
        float f2;
        long j;
        boolean infeasibleSystem2;
        int tries = 0;
        boolean infeasibleSystem3 = false;
        int i = 0;
        while (true) {
            f = 0.0f;
            if (i >= this.mNumRows) {
                break;
            }
            SolverVariable variable = this.mRows[i].mVariable;
            if (variable.mType == SolverVariable.Type.UNRESTRICTED || this.mRows[i].mConstantValue >= 0.0f) {
                i++;
            } else {
                infeasibleSystem3 = true;
                break;
            }
        }
        if (infeasibleSystem3) {
            boolean done = false;
            tries = 0;
            while (!done) {
                long j2 = 1;
                if (sMetrics != null) {
                    sMetrics.bfs++;
                }
                tries++;
                float min = Float.MAX_VALUE;
                int strength = 0;
                int pivotRowIndex = -1;
                int pivotColumnIndex = -1;
                int i2 = 0;
                while (i2 < this.mNumRows) {
                    ArrayRow current = this.mRows[i2];
                    SolverVariable variable2 = current.mVariable;
                    if (variable2.mType == SolverVariable.Type.UNRESTRICTED) {
                        infeasibleSystem = infeasibleSystem3;
                        f2 = f;
                        j = j2;
                    } else if (current.mIsSimpleDefinition) {
                        infeasibleSystem = infeasibleSystem3;
                        f2 = f;
                        j = j2;
                    } else if (current.mConstantValue >= f) {
                        infeasibleSystem = infeasibleSystem3;
                        f2 = f;
                        j = j2;
                    } else {
                        int i3 = 9;
                        if (SKIP_COLUMNS) {
                            int size = current.variables.getCurrentSize();
                            f2 = f;
                            int j3 = 0;
                            while (j3 < size) {
                                long j4 = j2;
                                SolverVariable candidate = current.variables.getVariable(j3);
                                float a_j = current.variables.get(candidate);
                                if (a_j <= f2) {
                                    infeasibleSystem2 = infeasibleSystem3;
                                } else {
                                    infeasibleSystem2 = infeasibleSystem3;
                                    int k = 0;
                                    while (k < i3) {
                                        float value = candidate.mStrengthVector[k] / a_j;
                                        if ((value < min && k == strength) || k > strength) {
                                            min = value;
                                            pivotRowIndex = i2;
                                            pivotColumnIndex = candidate.id;
                                            strength = k;
                                        }
                                        k++;
                                        i3 = 9;
                                    }
                                }
                                j3++;
                                j2 = j4;
                                infeasibleSystem3 = infeasibleSystem2;
                                i3 = 9;
                            }
                            infeasibleSystem = infeasibleSystem3;
                            j = j2;
                        } else {
                            infeasibleSystem = infeasibleSystem3;
                            f2 = f;
                            j = j2;
                            for (int j5 = 1; j5 < this.mNumColumns; j5++) {
                                SolverVariable candidate2 = this.mCache.mIndexedVariables[j5];
                                float a_j2 = current.variables.get(candidate2);
                                if (a_j2 > f2) {
                                    for (int k2 = 0; k2 < 9; k2++) {
                                        float value2 = candidate2.mStrengthVector[k2] / a_j2;
                                        if ((value2 < min && k2 == strength) || k2 > strength) {
                                            min = value2;
                                            pivotRowIndex = i2;
                                            pivotColumnIndex = j5;
                                            strength = k2;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    i2++;
                    f = f2;
                    j2 = j;
                    infeasibleSystem3 = infeasibleSystem;
                }
                boolean infeasibleSystem4 = infeasibleSystem3;
                float f3 = f;
                long j6 = j2;
                if (pivotRowIndex != -1) {
                    ArrayRow pivotEquation = this.mRows[pivotRowIndex];
                    pivotEquation.mVariable.mDefinitionId = -1;
                    if (sMetrics != null) {
                        sMetrics.pivots += j6;
                    }
                    pivotEquation.pivot(this.mCache.mIndexedVariables[pivotColumnIndex]);
                    pivotEquation.mVariable.mDefinitionId = pivotRowIndex;
                    pivotEquation.mVariable.updateReferencesWithNewDefinition(this, pivotEquation);
                } else {
                    done = true;
                }
                if (tries > this.mNumColumns / 2) {
                    done = true;
                }
                f = f3;
                infeasibleSystem3 = infeasibleSystem4;
            }
        }
        return tries;
    }

    private void computeValues() {
        for (int i = 0; i < this.mNumRows; i++) {
            ArrayRow row = this.mRows[i];
            row.mVariable.computedValue = row.mConstantValue;
        }
    }

    private void displayRows() {
        displaySolverVariables();
        String s = "";
        for (int i = 0; i < this.mNumRows; i++) {
            s = (s + this.mRows[i]) + "\n";
        }
        System.out.println(s + this.mGoal + "\n");
    }

    public void displayReadableRows() {
        displaySolverVariables();
        String s = " num vars " + this.mVariablesID + "\n";
        for (int i = 0; i < this.mVariablesID + 1; i++) {
            SolverVariable variable = this.mCache.mIndexedVariables[i];
            if (variable != null && variable.isFinalValue) {
                s = s + " $[" + i + "] => " + variable + " = " + variable.computedValue + "\n";
            }
        }
        String s2 = s + "\n";
        for (int i2 = 0; i2 < this.mVariablesID + 1; i2++) {
            SolverVariable variable2 = this.mCache.mIndexedVariables[i2];
            if (variable2 != null && variable2.mIsSynonym) {
                SolverVariable synonym = this.mCache.mIndexedVariables[variable2.mSynonym];
                s2 = s2 + " ~[" + i2 + "] => " + variable2 + " = " + synonym + " + " + variable2.mSynonymDelta + "\n";
            }
        }
        String s3 = s2 + "\n\n #  ";
        for (int i3 = 0; i3 < this.mNumRows; i3++) {
            s3 = (s3 + this.mRows[i3].toReadableString()) + "\n #  ";
        }
        if (this.mGoal != null) {
            s3 = s3 + "Goal: " + this.mGoal + "\n";
        }
        System.out.println(s3);
    }

    public void displayVariablesReadableRows() {
        displaySolverVariables();
        String s = "";
        for (int i = 0; i < this.mNumRows; i++) {
            if (this.mRows[i].mVariable.mType == SolverVariable.Type.UNRESTRICTED) {
                s = (s + this.mRows[i].toReadableString()) + "\n";
            }
        }
        System.out.println(s + this.mGoal + "\n");
    }

    public int getMemoryUsed() {
        int actualRowSize = 0;
        for (int i = 0; i < this.mNumRows; i++) {
            if (this.mRows[i] != null) {
                actualRowSize += this.mRows[i].sizeInBytes();
            }
        }
        return actualRowSize;
    }

    public int getNumEquations() {
        return this.mNumRows;
    }

    public int getNumVariables() {
        return this.mVariablesID;
    }

    void displaySystemInformation() {
        int rowSize = 0;
        for (int i = 0; i < this.mTableSize; i++) {
            if (this.mRows[i] != null) {
                rowSize += this.mRows[i].sizeInBytes();
            }
        }
        int actualRowSize = 0;
        for (int i2 = 0; i2 < this.mNumRows; i2++) {
            if (this.mRows[i2] != null) {
                actualRowSize += this.mRows[i2].sizeInBytes();
            }
        }
        System.out.println("Linear System -> Table size: " + this.mTableSize + " (" + getDisplaySize(this.mTableSize * this.mTableSize) + ") -- row sizes: " + getDisplaySize(rowSize) + ", actual size: " + getDisplaySize(actualRowSize) + " rows: " + this.mNumRows + "/" + this.mMaxRows + " cols: " + this.mNumColumns + "/" + this.mMaxColumns + " 0 occupied cells, " + getDisplaySize(0));
    }

    private void displaySolverVariables() {
        String s = "Display Rows (" + this.mNumRows + "x" + this.mNumColumns + ")\n";
        System.out.println(s);
    }

    private String getDisplaySize(int n) {
        int mb = ((n * 4) / 1024) / 1024;
        if (mb > 0) {
            return "" + mb + " Mb";
        }
        int kb = (n * 4) / 1024;
        return kb > 0 ? "" + kb + " Kb" : "" + (n * 4) + " bytes";
    }

    public Cache getCache() {
        return this.mCache;
    }

    private String getDisplayStrength(int strength) {
        if (strength == 1) {
            return "LOW";
        }
        if (strength == 2) {
            return "MEDIUM";
        }
        if (strength == 3) {
            return "HIGH";
        }
        if (strength == 4) {
            return "HIGHEST";
        }
        if (strength == 5) {
            return "EQUALITY";
        }
        if (strength == 8) {
            return "FIXED";
        }
        if (strength == 6) {
            return "BARRIER";
        }
        return "NONE";
    }

    public void addGreaterThan(SolverVariable a, SolverVariable b, int margin, int strength) {
        ArrayRow row = createRow();
        SolverVariable slack = createSlackVariable();
        slack.strength = 0;
        row.createRowGreaterThan(a, b, slack, margin);
        if (strength != 8) {
            float slackValue = row.variables.get(slack);
            addSingleError(row, (int) ((-1.0f) * slackValue), strength);
        }
        addConstraint(row);
    }

    public void addGreaterBarrier(SolverVariable a, SolverVariable b, int margin, boolean hasMatchConstraintWidgets) {
        ArrayRow row = createRow();
        SolverVariable slack = createSlackVariable();
        slack.strength = 0;
        row.createRowGreaterThan(a, b, slack, margin);
        addConstraint(row);
    }

    public void addLowerThan(SolverVariable a, SolverVariable b, int margin, int strength) {
        ArrayRow row = createRow();
        SolverVariable slack = createSlackVariable();
        slack.strength = 0;
        row.createRowLowerThan(a, b, slack, margin);
        if (strength != 8) {
            float slackValue = row.variables.get(slack);
            addSingleError(row, (int) ((-1.0f) * slackValue), strength);
        }
        addConstraint(row);
    }

    public void addLowerBarrier(SolverVariable a, SolverVariable b, int margin, boolean hasMatchConstraintWidgets) {
        ArrayRow row = createRow();
        SolverVariable slack = createSlackVariable();
        slack.strength = 0;
        row.createRowLowerThan(a, b, slack, margin);
        addConstraint(row);
    }

    public void addCentering(SolverVariable a, SolverVariable b, int m1, float bias, SolverVariable c, SolverVariable d, int m2, int strength) {
        ArrayRow row = createRow();
        row.createRowCentering(a, b, m1, bias, c, d, m2);
        if (strength != 8) {
            row.addError(this, strength);
        }
        addConstraint(row);
    }

    public void addRatio(SolverVariable a, SolverVariable b, SolverVariable c, SolverVariable d, float ratio, int strength) {
        ArrayRow row = createRow();
        row.createRowDimensionRatio(a, b, c, d, ratio);
        if (strength != 8) {
            row.addError(this, strength);
        }
        addConstraint(row);
    }

    public void addSynonym(SolverVariable a, SolverVariable b, int margin) {
        if (a.mDefinitionId == -1 && margin == 0) {
            if (b.mIsSynonym) {
                margin += (int) b.mSynonymDelta;
                b = this.mCache.mIndexedVariables[b.mSynonym];
            }
            if (a.mIsSynonym) {
                int i = margin - ((int) a.mSynonymDelta);
                SolverVariable a2 = this.mCache.mIndexedVariables[a.mSynonym];
                return;
            } else {
                a.setSynonym(this, b, 0.0f);
                return;
            }
        }
        addEquality(a, b, margin, 8);
    }

    public ArrayRow addEquality(SolverVariable a, SolverVariable b, int margin, int strength) {
        if (sMetrics != null) {
            sMetrics.mSimpleEquations++;
        }
        if (USE_BASIC_SYNONYMS && strength == 8 && b.isFinalValue && a.mDefinitionId == -1) {
            a.setFinalValue(this, b.computedValue + margin);
            return null;
        }
        ArrayRow row = createRow();
        row.createRowEquals(a, b, margin);
        if (strength != 8) {
            row.addError(this, strength);
        }
        addConstraint(row);
        return row;
    }

    public void addEquality(SolverVariable a, int value) {
        if (sMetrics != null) {
            sMetrics.mSimpleEquations++;
        }
        if (USE_BASIC_SYNONYMS && a.mDefinitionId == -1) {
            a.setFinalValue(this, value);
            for (int i = 0; i < this.mVariablesID + 1; i++) {
                SolverVariable variable = this.mCache.mIndexedVariables[i];
                if (variable != null && variable.mIsSynonym && variable.mSynonym == a.id) {
                    variable.setFinalValue(this, value + variable.mSynonymDelta);
                }
            }
            return;
        }
        int idx = a.mDefinitionId;
        if (a.mDefinitionId != -1) {
            ArrayRow row = this.mRows[idx];
            if (row.mIsSimpleDefinition) {
                row.mConstantValue = value;
                return;
            }
            if (row.variables.getCurrentSize() == 0) {
                row.mIsSimpleDefinition = true;
                row.mConstantValue = value;
                return;
            } else {
                ArrayRow newRow = createRow();
                newRow.createRowEquals(a, value);
                addConstraint(newRow);
                return;
            }
        }
        ArrayRow row2 = createRow();
        row2.createRowDefinition(a, value);
        addConstraint(row2);
    }

    public static ArrayRow createRowDimensionPercent(LinearSystem linearSystem, SolverVariable variableA, SolverVariable variableC, float percent) {
        ArrayRow row = linearSystem.createRow();
        return row.createRowDimensionPercent(variableA, variableC, percent);
    }

    public void addCenterPoint(ConstraintWidget widget, ConstraintWidget target, float angle, int radius) {
        SolverVariable Al = createObjectVariable(widget.getAnchor(ConstraintAnchor.Type.LEFT));
        SolverVariable At = createObjectVariable(widget.getAnchor(ConstraintAnchor.Type.TOP));
        SolverVariable Ar = createObjectVariable(widget.getAnchor(ConstraintAnchor.Type.RIGHT));
        SolverVariable Ab = createObjectVariable(widget.getAnchor(ConstraintAnchor.Type.BOTTOM));
        SolverVariable Bl = createObjectVariable(target.getAnchor(ConstraintAnchor.Type.LEFT));
        SolverVariable Bt = createObjectVariable(target.getAnchor(ConstraintAnchor.Type.TOP));
        SolverVariable Br = createObjectVariable(target.getAnchor(ConstraintAnchor.Type.RIGHT));
        SolverVariable Bb = createObjectVariable(target.getAnchor(ConstraintAnchor.Type.BOTTOM));
        ArrayRow row = createRow();
        float angleComponent = (float) (radius * Math.sin(angle));
        row.createRowWithAngle(At, Ab, Bt, Bb, angleComponent);
        addConstraint(row);
        ArrayRow row2 = createRow();
        float angleComponent2 = (float) (Math.cos(angle) * radius);
        row2.createRowWithAngle(Al, Ar, Bl, Br, angleComponent2);
        addConstraint(row2);
    }
}
