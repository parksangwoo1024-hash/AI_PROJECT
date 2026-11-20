# Security Specification — 나의 AI 프롬프트 창고

## 1. Data Invariants
1. **Access Control**:
   - **Read (`get`, `list`) on `/prompts/{promptId}`**: Anyone can read without signing in.
   - **Write (`create`, `update`, `delete`) on `/prompts/{promptId}`**: Strictly restricted to verified Google account `parksangwoo1024@gmail.com` (`request.auth != null && request.auth.token.email == 'parksangwoo1024@gmail.com' && request.auth.token.email_verified == true`).
   - **All Other Collections**: All reads and writes are denied by default (`allow read, write: if false;`).
2. **Prompt Schema Integrity**: Every document in `/prompts/{promptId}` must contain strictly and only `['title', 'category', 'content', 'createdAt']`.
3. **Boundary & Type Enforcement**:
   - `title`: non-empty string, `1 <= size <= 100`.
   - `category`: strictly one of `'사진 합성'`, `'스타일 변환'`, `'캐릭터·포스터'`.
   - `content`: non-empty string, `1 <= size <= 10000` (supports 1,000+ character prompts).
   - `createdAt`: Firestore server `timestamp`, strictly equal to `request.time` on `create` and immutable on `update`.
4. **Path Variable Hardening**: `promptId` must match `^[a-zA-Z0-9_-]+$` and `1 <= size <= 128`.

## 2. The "Dirty Dozen" Payloads (Expected: PERMISSION_DENIED)
1. Unauthenticated `create` / `update` / `delete` on `/prompts/*`.
2. Authenticated non-admin email (e.g. `other@gmail.com`) `create` / `update` / `delete`.
3. Spoofed admin email with `email_verified: false`.
4. Shadow Field Injection (`isAdmin: true`).
5. Missing Required Field (`content` omitted).
6. Invalid Category Enum (`"기타"`).
7. Empty or Oversized Title (`""` or 101 chars).
8. Empty or Oversized Content (`""` or 10,001 chars).
9. Forged Client Timestamp on Create (`createdAt != request.time`).
10. Mutating `createdAt` on Update.
11. Type Poisoning (`title: 123`).
12. Unauthorized Collection Read/Write (`/users/hacked`, `/test/connection`, `/admins/me`).
