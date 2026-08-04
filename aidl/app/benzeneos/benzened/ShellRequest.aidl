package app.benzeneos.benzened;

parcelable ShellRequest {
    String command;
    boolean terminal;
    int columns;
    int rows;
    @nullable String workingDirectory;
    String[] environment;
}
