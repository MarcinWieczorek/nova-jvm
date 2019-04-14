class Add {
    public static int field1;

    public static void main(String[] args) {
        testLoop(5);
        testAdd();
        testField();
    }

    public static void testLoop(int max) {
        int a = 0;
        for(int i = 0; i < max; i++) {
            a += i;
        }
        System.out.println(a);
    }

    public static void testAdd() {
        int a = 123;
        int b = 321;
        int c = a + b;
        System.out.println(c);
    }

    public static void testField() {
        int a = 12;
        Add.field1 = a;
        int b = Add.field1;
        System.out.println(b);
    }
}
