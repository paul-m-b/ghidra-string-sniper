package ghidra_string_sniper;

public class ResultData {
    public float score;
    public int confidence;
    public String hash;
    public Double entropy;
    public StringData string;

    public ResultData(float score, int confidence, String hash, Double entropy, StringData string) {
        this.score = score;
        this.confidence = confidence;
        this.hash = hash;
        this.entropy = entropy;
        this.string = string;
    }
}
