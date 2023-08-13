
import java.io.File;

public class AddFilesRQ {
    private Integer chunkNumber = 1;
    private Integer resumableTotalChunks = 1;
    private String resumableRelativePath;
    private String resumableType;
    private String fileName;
    private String resumableIdentifier;
    private File file;

    public String getResumableRelativePath() {
        return resumableRelativePath;
    }

    public void setResumableRelativePath(String resumableRelativePath) {
        this.resumableRelativePath = resumableRelativePath;
    }

    public Integer getChunkNumber() {
        return chunkNumber;
    }

    public void setChunkNumber(Integer chunkNumber) {
        this.chunkNumber = chunkNumber;
    }

    public Integer getResumableTotalChunks() {
        return resumableTotalChunks;
    }

    public void setResumableTotalChunks(Integer resumableTotalChunks) {
        this.resumableTotalChunks = resumableTotalChunks;
    }

    public String getResumableType() {
        return resumableType;
    }

    public void setResumableType(String resumableType) {
        this.resumableType = resumableType;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getResumableIdentifier() {
        return resumableIdentifier;
    }

    public void setResumableIdentifier(String resumableIdentifier) {
        this.resumableIdentifier = resumableIdentifier;
    }

    public File getFile() {
        return file;
    }

    public void setFile(File file) {
        this.file = file;
    }
}
