package ghidra_string_sniper;

public class ResultData {
    public float score;        // Ranking score (Sniper score)
    public int confidence;     // JSON field
    public String hash;        // JSON field
    public Double entropy;     // JSON field
    public StringData string;

    public ResultData(float score, int confidence, String hash, Double entropy, StringData string) {
        this.score = score;
        this.confidence = confidence;
        this.hash = hash;
        this.entropy = entropy;
        this.string = string;
    }
}
