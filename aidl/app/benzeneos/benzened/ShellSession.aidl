package app.benzeneos.benzened;

parcelable ShellSession {
    ParcelFileDescriptor inputOutput;
    @nullable ParcelFileDescriptor standardError;
    ParcelFileDescriptor exitStatus;
}
