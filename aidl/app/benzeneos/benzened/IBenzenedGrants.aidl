package app.benzeneos.benzened;

interface IBenzenedGrants {
    const String SERVICE_NAME = "app.benzeneos.benzened.IBenzenedGrants/default";
    const int TIER_NONE = 0;
    const int TIER_STANDARD = 1;
    const int TIER_UNRESTRICTED = 2;

    int getRootTier(int uid);
}
