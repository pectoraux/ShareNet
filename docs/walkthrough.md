# ShareNet "Offline Hub" & Mesh Economy Walkthrough

ShareNet has been expanded from a content mesh into a comprehensive "Offline Hub" ecosystem with a sustainable mesh-based economic model.

## Key Features

### 1. App Hub (Offline App Store)
- **Concept**: A central place to discover and "install" offline clones of popular services (Chat, Games, Payments).
- **Implementation**: Clones are delivered as `Category.APP_BUNDLE` blobs and executed within a secure container in the `:app-feed` application.
- **Integration**: Navigable via the new "Hub" 🚀 tab in the reference app.

### 2. Mesh Economy (Civic Points & Ad Revenue)
- **Internet Bridging**: Nodes now earn **Bridging Points** (5x base reward) for fetching content from the real internet and introducing it to the mesh.
- **Ad Distribution**:
    - Introduced `Category.AD` for businesses to buy mesh-wide visibility.
    - **Revenue Split**: 70% of ad bounties flow to the "Bridgers", 20% to the "Deliverers", and 10% to the platform.
    - **Ad Injector**: The `FeedRepository` automatically interleaves ads every 5 posts in the feed.

### 3. Keypad Phone Accessibility (SmsGateway)
- **SMS Bridge**: A new `SmsGateway` in `core-transport` allows non-smartphones to participate in the mesh.
- **Structured Commands**: Keypad users can send SMS messages like `SN LIKE <BLOB_HEX>` to a nearby Android gateway node, which injects the action into the global mesh queue.

## Changes Walkthrough

### Core Modules
- **`core-crypto`**: Added `APP_BUNDLE` and `AD` categories.
- **`core-attest`**: Enhanced `PointsLedger` with bridging logic and ad multipliers.
- **`core-transport`**: Implemented `SmsGateway` for structured command parsing.

### ShareNet Feed
- **`AppHubRepository`**: Added discovery logic for app bundles.
- **`FeedRepository`**: Implemented `interleaveAds` logic for optimistic feed rendering.

### Reference App
- **`MainActivity`**: Added Navigation support for the "App Hub".
- **`HubScreen`**: A reference UI for discovering offline clones.

## Verification Results
- **Unit Tests**: `:sharenet-feed:test` passed, verifying optimistic updates and ad-interleaving logic.
- **Build**: `:app-feed:assembleDebug` successful with resolved Material3 theme issues.
- **Repository**: Project pushed to [github.com/pectoraux/ShareNet](https://github.com/pectoraux/ShareNet).

---

> [!TIP]
> To test the economy logic, you can trigger a mock ad delivery in unit tests and verify the `PointsLedger` balance splits.
