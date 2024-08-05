#include "tools/fuzzing/include/test_case.hh"
#include <cstring> // For memcpy

// Constructors
TestCase::TestCase()
    : fuzz_iteration(0), data_size(0), data(nullptr) {}

TestCase::TestCase(int iteration, size_t size, const uint8_t* data)
    : fuzz_iteration(iteration), data_size(size), data(std::make_unique<uint8_t[]>(size)) {
    std::memcpy(this->data.get(), data, size);
}

TestCase::TestCase(int iteration, size_t size, std::unique_ptr<uint8_t[]> data)
    : fuzz_iteration(iteration), data_size(size), data(std::move(data)) {}

// Copy Constructor
TestCase::TestCase(const TestCase& other)
    : fuzz_iteration(other.fuzz_iteration), data_size(other.data_size), data(std::make_unique<uint8_t[]>(other.data_size)) {
    std::memcpy(data.get(), other.data.get(), other.data_size);
}

// Move Constructor
TestCase::TestCase(TestCase&& other) noexcept
    : fuzz_iteration(other.fuzz_iteration), data_size(other.data_size), data(std::move(other.data)) {
    other.fuzz_iteration = 0;
    other.data_size = 0;
}

// Copy Assignment Operator
TestCase& TestCase::operator=(const TestCase& other) {
    if (this != &other) {
        fuzz_iteration = other.fuzz_iteration;
        data_size = other.data_size;
        data = std::make_unique<uint8_t[]>(other.data_size);
        std::memcpy(data.get(), other.data.get(), other.data_size);
    }
    return *this;
}

// Move Assignment Operator
TestCase& TestCase::operator=(TestCase&& other) noexcept {
    if (this != &other) {
        fuzz_iteration = other.fuzz_iteration;
        data_size = other.data_size;
        data = std::move(other.data);

        other.fuzz_iteration = 0;
        other.data_size = 0;
    }
    return *this;
}

// Destructor
TestCase::~TestCase() = default;

// Getters
int TestCase::getFuzzIteration() const {
    return fuzz_iteration;
}


size_t TestCase::getDataSize() const {
    return data_size;
}

const uint8_t* TestCase::getData() const {
    return data.get();
}

// Setters
void TestCase::setFuzzIteration(int iteration) {
    fuzz_iteration = iteration;
}

void TestCase::setDataSize(size_t size) {
    data_size = size;
}

void TestCase::setData(const uint8_t* newData, size_t size) {
    data = std::make_unique<uint8_t[]>(size);
    std::memcpy(data.get(), newData, size);
    data_size = size;
}

void TestCase::setData(std::unique_ptr<uint8_t[]> newData, size_t size) {
    data = std::move(newData);
    data_size = size;
}

// Utility Methods
void TestCase::clear() {
    fuzz_iteration = 0;
    data_size = 0;
    data.reset();
}

void TestCase::print() const {
    std::cout << "Fuzz Iteration: " << fuzz_iteration << "\n";
    std::cout << "Data Size: " << data_size << "\n";
    std::cout << "Data: ";
    for (size_t i = 0; i < data_size; ++i) {
        std::cout << static_cast<int>(data[i]) << " ";
    }
    std::cout << "\n";
}
