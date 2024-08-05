#ifndef TESTCASE_H
#define TESTCASE_H

#include <memory>
#include <cstddef>
#include <iostream>

class TestCase {
public:
    // Constructors
    TestCase();
    TestCase(int iteration, size_t size, const uint8_t* data);
    TestCase(int iteration, size_t size, std::unique_ptr<uint8_t[]> data);

    // Copy Constructor
    TestCase(const TestCase& other);

    // Move Constructor
    TestCase(TestCase&& other) noexcept;

    // Copy Assignment Operator
    TestCase& operator=(const TestCase& other);

    // Move Assignment Operator
    TestCase& operator=(TestCase&& other) noexcept;

    // Destructor
    ~TestCase();

    // Getters
    int getFuzzIteration() const;
    size_t getDataSize() const;
    const uint8_t* getData() const;

    // Setters
    void setFuzzIteration(int iteration);
    void setDataSize(size_t size);
    void setData(const uint8_t* newData, size_t size);
    void setData(std::unique_ptr<uint8_t[]> newData, size_t size);

    // Utility Methods
    void clear();
    void print() const;

private:
    int fuzz_iteration;
    size_t data_size;
    std::unique_ptr<uint8_t[]> data;
};

#endif // TESTCASE_H

