# Task Completion Checklist

## Before Completing a Task
1. [ ] Code compiles/runs without errors
2. [ ] No sensitive data in logs or responses
3. [ ] Security headers properly configured
4. [ ] Rate limiting in place
5. [ ] Input validation for all user inputs
6. [ ] Error handling implemented

## Testing Requirements
1. [ ] Run `npm start` to verify server starts
2. [ ] Test file sharing flow in browser
3. [ ] Verify encryption works
4. [ ] Check no data leaks in network traffic
5. [ ] Run Playwright regression tests

## Security Verification
1. [ ] No IP addresses logged (for anonymous mode)
2. [ ] No timing information exposed
3. [ ] Headers don't reveal server info
4. [ ] Files are encrypted before transfer
5. [ ] Tokens expire correctly

## Documentation
1. [ ] Update CLAUDE.md if needed
2. [ ] Update README.md if user-facing changes
3. [ ] Add inline comments for complex logic
