package ghidra_string_sniper;

public class StringData {
    public String value;
    public String address;
    public Float score;
    public Integer resultsScore;
    public Float entropy;
    public String matchPath;

    public StringData(String value, String address) {
        this.value = value;
        this.address = address;
        this.score = null;
    }

    public StringData(String value, String address, Float score) {
        this.value = value;
        this.address = address;
        this.score = score;
    }

    public StringData(String value, String address, Float score, Integer resultsScore, Float entropy) {
        this.value = value;
        this.address = address;
        this.score = score;
        this.resultsScore = resultsScore;
        this.entropy = entropy;
    }

    @Override
    public String toString() {
        return value;
    }
}
