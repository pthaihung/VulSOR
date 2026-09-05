int consume(int value) {
    return value + 1;
}

int target(int input) {
    if (input > 0) {
        return consume(input);
    }
    return 0;
}
