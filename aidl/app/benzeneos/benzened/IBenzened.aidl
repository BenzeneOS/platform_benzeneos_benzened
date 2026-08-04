package app.benzeneos.benzened;

import app.benzeneos.benzened.ShellRequest;
import app.benzeneos.benzened.ShellSession;

interface IBenzened {
    const String SERVICE_NAME = "app.benzeneos.benzened.IBenzened/default";

    ShellSession openShell(in ShellRequest request);
}
